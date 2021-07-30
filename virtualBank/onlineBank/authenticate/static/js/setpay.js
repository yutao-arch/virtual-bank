function setpay() {
    //得到表单中的各种信息
    var setpay_host = window.location.href;
    var passwd = document.getElementById("password");
    var re_passwd = document.getElementById("re-password");
    var post_data = {
        "set": true   //用于在set_paypasswd方法中判断，默认为true
    };
    if (passwd.value != re_passwd.value) {  //对于密码不一致的情况
        alert("输入两次密码不一致");
        $('#password').val("");
        $('#re-password').val("");
        passwd.focus();
        return false;
    }
    $.post(
        setpay_host,  //相当于第一次调用views中的用于在set_paypasswd方法，此时si_request为true，然后返回RSA公钥pub_key到前端
        post_data,
        function (data, status) {
            pub_key = data.pub_key
            var encrypt = new JSEncrypt();
            encrypt.setPublicKey(pub_key);
            post_data.set = false;
            post_data.passwd = encrypt.encrypt($('#password').val());  //对支付密码使用RSA公钥加密
            $.post(  //相当于第二次调用views中的用于在set_paypasswd方法，此时si_request为false，然后返回message或者跳转后的url到前端
                setpay_host,
                post_data,
                function (data, status) {
                    var message = data.message
                    if (message) {
                        $('#prompt').html("<div class='alert alert-success' role='alert'>" + message + ".</div>")
                    }
                    if (data.url) {
                        setTimeout(function () {
                            window.location.href = data.url;
                        }, 2000);
                    }
                    return false
                }
            )
        });
    window.event.returnValue = false;
}