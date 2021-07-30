function transfer()
{
    // 处理各种错误
    if ($('#phone').val() == "") {
        alert("请填写联系电话");
        $('#name').focus();
        return false;
    }
    if ($('#b_phone').val() == "") {
        alert("请填写收款人电话号码");
        $('#b_phone').focus();
        return false;
    }
    if ($('#amount').val() == "") {
        alert("请填写银行卡号");
        $('#amount').focus();
        return false;
    }
    if ($('#passwd').val() == "" || $('#retype').val() == "") {
        alert("请输入密码");
        $('#passwd').focus();
        return false;
    }
    if ($('#passwd').val() != $('#retype').val()) {
        alert("两次密码不一致");
        $('#passwd').val("");
        $('#retype').val("");
        $('#passwd').focus();
        return false;
    }
    var salt = getsalt(); //得到随机盐值，为了防重放
    var pub_encrypt = get_serverPub(); //得到服务器公钥
    post_data = {};
    post_data.amount = pub_encrypt.encrypt($('#amount').val());  // 用服务器使用RSA公钥加密金额
    var first = CryptoJS.MD5($('#passwd').val()).toString() //将密码首先使用MD5哈希散列
    var after = CryptoJS.MD5(first + salt).toString() //然后将散列后的值与盐值相加然后再使用MD5哈希散列
    post_data.passwd = pub_encrypt.encrypt(after)  //再使用RSA公钥加密得到最终加密的密码
    post_data.b_phone = pub_encrypt.encrypt($('#b_phone').val());//使用RSA公钥加密手机号码
    post_data.phone = pub_encrypt.encrypt($('#phone').val());//使用RSA公钥加密手机号码
    var pri_encrypt = get_private();
    post_data.signature = pri_encrypt.sign(post_data.amount + post_data.passwd+ post_data.b_phone+ post_data.phone, CryptoJS.SHA256, "sha256");  // 构建数字签名
    $.ajaxSettings.async = false;
    $.post(
        window.location.href,  // 对于当前窗口，相当于调用views中的transfer方法
        post_data,
        function (data, status) {
            if (data.message) {
                $('#prompt').html("<div class='alert alert-success' role='alert'>" + data.message + ".</div>")
            }
            if (data.success) {    // 后端返回的success==True
                $.ajaxSettings.async = true;
                setTimeout(function () {
                    window.location.href = home_host; // 返回主页
                }, 1000);
            }
            return false;
        }
    )
    window.event.returnValue = false;
}