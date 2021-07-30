function signup() {
    //得到表单中的各种信息
    var name = document.getElementById("name");
    var phone = document.getElementById("phone");
    var card = document.getElementById("card");
    var id = document.getElementById("id_no");
    var passwd = document.getElementById("password");
    var re_passwd = document.getElementById("re-password");
    var post_data = {
        'signup_request': true,  //用于在su_request方法中判断，默认为true
    };
    var pub_key;
    //对各种非法条件进行判断
    if ($('#name').val() == "") {
        alert("请填写用户名");
        name.focus();
        return false;
    }
    if (phone.value == "") {
        alert("请填写联系电话");
        phone.focus();
        return false;
    }
    if (id.value == "") {
        alert("请填写身份证号码");
        id.focus();
        return false;
    }
    if (card.value == "") {
        alert("请填写银行卡号");
        card.focus();
        return false;
    }
    if (passwd.value == "" || re_passwd.value == "") {
        alert("请输入密码");
        passwd.focus();
        return false;
    }
    if (passwd.value != re_passwd.value) {
        alert("两次密码不一致");
        $('#password').val("");
        $('#re-password').val("");
        passwd.focus();
        return false;
    }
    $.post(
        post_host,  //相当于第一次调用views中的su_request方法，此时signup_request为true，创建了公钥然后返回RSA公钥pub_key到前端
        post_data,
        function (data, status) {
            pub_key = data.pub_key
            //使用创建的服务器公钥
            var encrypt = new JSEncrypt();
            encrypt.setPublicKey(pub_key);
            //对用户的个人信息使用pub_key加密
            post_data.signup_request = false;
            post_data.name = encrypt.encrypt(name.value);
            post_data.phone = encrypt.encrypt(phone.value);
            post_data.id_no = encrypt.encrypt(id.value);
            post_data.card = encrypt.encrypt(card.value);
            post_data.passwd = encrypt.encrypt(passwd.value);
            console.log(post_data);  //记录日志
            $.post(
                post_host,
                //相当于第二次调用views中的su_request方法，此时signup_request为false，
                // 将所有加密后的数据发送给后台，然后后台进行解密写进数据库(在其中还完成了对密码的散列)，返回saved=True到前端
                post_data,
                function (data, status) {
                    console.log(data);
                    if (data.saved){
                        window.location.href=prompt_host;  //跳转到注册成功的页面
                    }
                    return data.saved;
                })
            return false;
        });
    window.event.returnValue=false;
}

function re_direct() {
    //再次进入登录页面
    window.location.href = signin_host;
    window.event.returnValue=false;
}