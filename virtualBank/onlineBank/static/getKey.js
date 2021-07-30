function get_private() {
    // 得到用户私钥
    var key = localStorage.getItem(window.name);
    var pri_encrypt = new JSEncrypt();
    pri_encrypt.setPrivateKey(key);
    return pri_encrypt;
}

function get_serverPub() {
    // 得到服务器的公钥
    var post_data = {
        'signup_request': true,
    };
    var pub_key;
    var pub_encrypt
    $.ajaxSettings.async = false;
    $.post(
        post_host,
        post_data,
        function (data, status) {
            pub_key = data.pub_key;
            pub_encrypt = new JSEncrypt();
            pub_encrypt.setPublicKey(pub_key);
        });
    $.ajaxSettings.async = true;
    return pub_encrypt;
}

function randomWord(len) {
    var str = "",
        range = len,
        arr = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'];
    for (var i = 0; i < range; i++) {
        pos = Math.round(Math.random() * (arr.length - 1));
        str += arr[pos];
    }
    return str;
}

function encrypt(msg, key) {
    var a = CryptoJS.AES.encrypt(msg, key, {
        iv: key,
        padding: CryptoJS.pad.Pkcs7,
        mode: CryptoJS.mode.CBC
    }).ciphertext;
    a = CryptoJS.enc.Base64.stringify(a);
    a = a.toString();
    return a;
}
function decrypt(cipherText, key) {
    cipherText=atob(cipherText)
    var cipherText = CryptoJS.enc.Latin1.parse(cipherText);
    console.log(cipherText);
    var a=CryptoJS.AES.decrypt({ ciphertext: cipherText }, key, {
        iv: key,
        padding: CryptoJS.pad.Pkcs7,
        mode: CryptoJS.mode.CBC
    });
    a = CryptoJS.enc.Latin1.stringify(a);
    //a=a.toString(CryptoJS.enc.Utf8)
    //a=a.toString();
    console.log(a);
    return a;
}

function returnhome() {
    // 用户设置私钥并返回主页
    var text = $('#text').val();
    if (text == "") {
        alert("请输入私钥");
        $('#text').focus();
        return false;
    }
    // alert(text)
    // localStorage.clear()
    // change("recharge");
    private_key = text
    localStorage.setItem(window.name, private_key)
    var key = localStorage.getItem(window.name);
    if (key != null) {
        window.location.href = window.home_host
    }
    window.event.returnValue = false;
}


function returnpay() {
    // 用户设置私钥并返回主页
    var text = $('#text').val();
    if (text == "") {
        alert("请输入私钥");
        $('#text').focus();
        return false;
    }
    // alert(text)
    // localStorage.clear()
    // change("recharge");
    private_key = text
    localStorage.setItem(window.name, private_key)
    var key = localStorage.getItem(window.name);
    if (key != null) {
        window.location.href = window.pay_host
    }
    window.event.returnValue = false;
}


