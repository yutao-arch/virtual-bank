function getsalt(){
    // 得到随机盐值，并储存在session中
    var salt;
    $.ajaxSettings.async = false;
    $.post(
        window.salt_host,
        '',
        function (data, status) {
            salt = data.salt;
        }
    )
    $.ajaxSettings.async = true;
    return salt;
}
function recharge() {
    var salt = getsalt();  //得到随机盐值，为了防重放
    var pub_encrypt = get_serverPub(); //得到服务器公钥
    post_data = {};
    post_data.amount = pub_encrypt.encrypt($('#amount').val());  // 用服务器使用RSA公钥加密金额
    var first = CryptoJS.MD5($('#password').val()).toString() //将密码首先使用MD5哈希散列
    var after = CryptoJS.MD5(first + salt).toString()  //然后将散列后的值与盐值相加然后再使用MD5哈希散列
    post_data.passwd = pub_encrypt.encrypt(after);   //再使用RSA公钥加密得到最终加密的密码
    var pri_encrypt = get_private();  //得到私钥
    post_data.signature = pri_encrypt.sign(post_data.amount + post_data.passwd, CryptoJS.SHA256, "sha256");  // 构建数字签名
    console.log(post_data);
    $.ajaxSettings.async = false;
    $.post(
        window.location.href,  // 对于当前窗口，相当于调用views中的recharge方法
        post_data,
        function (data, status) {
            if (data.message) {
                $('#prompt').html("<div class='alert alert-success' role='alert'>" + data.message + ".</div>")
            }
            if (data.success) {  // 后端返回的success==True
                $.ajaxSettings.async = true;
                setTimeout(function () {
                    window.location.href = home_host;  // 返回主页
                }, 1000);
            }
            return false;
        }
    )
    window.event.returnValue = false;
}