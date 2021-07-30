(function(){
    $("#card").on("keyup",function(){
    var caret = this.selectionStart;
    var value = this.value;
    var sp =  (value.slice(0, caret).match(/\s/g) || []).length;
    var nospace = value.replace(/\s/g, '');
    var curVal = this.value = nospace.replace(/\D+/g,"").replace(/(\d{4})/g, "$1 ").trim();
    var curSp = (curVal.slice(0, caret).match(/\s/g) || []).length;
    this.selectionEnd = this.selectionStart = caret + curSp - sp;
    });
})();