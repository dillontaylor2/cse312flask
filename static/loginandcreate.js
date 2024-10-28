var Rotation = 0
function rotate(){
    var img = document.getElementById("logo");
    Rotation = Rotation - 90;
    img.style.transform = "rotate("+Rotation.toString()+"deg)";
    console.log("flip");
}
