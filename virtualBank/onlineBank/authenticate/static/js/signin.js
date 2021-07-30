function signin() {
    var post_data = {
        "si_request": true  //用于在sign_in方法中判断，默认为true
    };
    $.post(
        signin_host,  //相当于第一次调用views中的signin方法，此时si_request为true，然后返回RSA公钥pub_key和盐值到前端
        post_data,
        function (data, status) {
            pub_key = data.pub_key;
            salt = data.salt;  // 获取后端的盐值
            salt_id = data.salt_id;
            var encrypt = new JSEncrypt();
            encrypt.setPublicKey(pub_key);
            post_data.si_request = false;
            post_data.name = encrypt.encrypt($('#username').val());  //用户名仅仅只使用RSA公钥加密
            var first = CryptoJS.MD5($('#password').val()).toString()  //将密码首先使用MD5哈希散列
            var after = CryptoJS.MD5(first + salt).toString()  //然后将散列后的值与盐值相加然后再使用MD5哈希散列
            post_data.passwd = encrypt.encrypt(after);  //再使用RSA公钥加密得到最终加密的密码
            post_data.salt_id = salt_id;
            $.post(
                signin_host,  //相当于第二次调用views中的signin方法，此时si_request为false，然后进行用户账户的检查判断，返回要跳转的url和可能会出现的message
                post_data,
                function (data, status) {
                    if (data.if_success) {
                        window.location.href = data.url;  //进入登录后的界面
                    }
                    var message = data.message
                    if (message) {
                        $('#prompt').html("<div class='alert alert-success' role='alert'>" + message + ".</div>")
                    }
                    return false
                }
            )
        });
    window.event.returnValue = false;
}


function pay(){
    var phone = $('#phone').val();
    var passwd = $('#password').val();
    var post_data = {
        "if_has_private": false
    };
    if (phone == "") {
        alert("请填写电话号码");
        $('#phone').focus();
        return false;
    }
    if (passwd == "") {
        alert("请填写支付密码");
        $('#password').focus();
        return false;
    }
    pub_key = get_serverPub();  //这是一个封装JSEncrypt，用RSA公钥的的函数
    // 公钥加密
    var salt = window.temp_salt  //从前端传来的随机盐值，用于防重放
    post_data.phone = pub_key.encrypt(phone);
    var first = CryptoJS.MD5(passwd).toString()  //将密码首先使用MD5哈希散列
    var after = CryptoJS.MD5(first + salt).toString()  //然后将散列后的值与盐值相加然后再使用MD5哈希散列
    post_data.passwd = pub_key.encrypt(after);
    post_data.pay_id = pub_key.encrypt(window.pay_id);
    $.post(
        window.pay_host,  //相当于调用views中的pay()方法
        post_data,
        function (data, status) {
            var key = localStorage.getItem(data.name)
            if (data.name == undefined){  // 如果没有该用户
                 $('#prompt').html("<div class='alert alert-success' role='alert'>" + data.message + ".</div>")
                window.location.href = window.pay_host
            }
            // 身份验证，电脑本地没有该用户的私钥，需要输入私钥
            else if (key == null) {
                window.verify_for_pay_host = "/authen/verify_for_pay/"+pay_id+"/"+data.name
                window.location.href = window.verify_for_pay_host;
            }
            //  成功的情况下
            else{
                post_data.if_has_private = true;
                var pri_encrypt = new JSEncrypt();
                pri_encrypt.setPrivateKey(key);
                // alert(pri_encrypt)
                post_data.signature = pri_encrypt.sign(post_data.phone + post_data.passwd, CryptoJS.SHA256, "sha256");  // 构建数字签名
                post_data.name = data.name;
                $.post(
                    window.pay_host,
                    post_data,
                    function (data, status) {
                        var message = data.message;
                        if (message) {
                             $('#prompt').html("<div class='alert alert-success' role='alert'>" + message + ".</div>")
                            window.location.href =  window.pay_host;
                        }
                        if(data.if_success){
                             window.location.href = data.to_go_url;  // 跳转到商家页面
                        }
                    })
            }
        })
    window.event.returnValue = false;
}

