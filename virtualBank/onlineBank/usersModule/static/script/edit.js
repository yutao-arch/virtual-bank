function edit() {
    post_data = {};
    var pub_encrypt = get_serverPub(); // 得到服务器公钥
    // 分别得到表单中的各种信息并都使用服务器RSA公钥加密
    if ($('#ppasswd').val() != "") {
        post_data.ppasswd = pub_encrypt.encrypt($('#ppasswd').val());
    }
    if ($('#card').val() != "") {
        post_data.card = pub_encrypt.encrypt($('#card').val());
    }
    if ($('#phone').val() != "") {
        post_data.phone = pub_encrypt.encrypt($('#phone').val());
    }
    if ($('#passwd').val() != "") {
        post_data.passwd = pub_encrypt.encrypt($('#passwd').val());
    }
    if ($('#opasswd').val() == "") {  // 必须输入旧的密码
        alert("请输入旧的支付密码");
        $('#opasswd').focus();
        return false;
    }
    else {
        post_data.opasswd = pub_encrypt.encrypt($('#opasswd').val());
    }
    $.ajaxSettings.async = false;
    $.post(
        window.location.href,  // 对于当前窗口，相当于调用views中的edit方法
        post_data,
        function (data, status) {  // 输出前端的信息message
            if (data.message) {
                alert(data.message);
            }
            if (data.success) {
                $.ajaxSettings.async = true;
                setTimeout(function () {
                    var tempname = data.name
                    window.location.href = info_host;  // 修改成功的话跳转到个人信息页面
                }, 1000);
            }
            return false;
        }
    )
    window.event.returnValue = false;
}