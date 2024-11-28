function changecolor(){
    let colors = ["pink","red","orange","yellow","green","blue","purple"]
    const list = document.createElement("ul");
        for (let color of colors){

        const elem = document.createElement("li");
        const colorC = document.createElement("input")
        const colorL = document.createElement("label")
        colorL.innerHTML = color;
        colorC.setAttribute('type', 'checkbox');
        colorC.setAttribute('class', 'colorcheck');
        colorC.setAttribute('color', color);

        elem.appendChild(colorL);
        colorL.insertAdjacentElement("beforebegin",colorC)
        list.appendChild(elem);
    }

    document.getElementById("profileContainer").appendChild(list)
    const button = document.getElementById("changeColor")
    button.setAttribute("value", "Change Me!")
    button.setAttribute("onclick","submitColor()")
}

function submitColor(){
    let colors = []
    for (let elements of document.getElementsByClassName("colorcheck")){
        if (elements.checked){
            colors.push(elements.getAttribute("color"))
        }

    }
     const request = new XMLHttpRequest();
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            location.reload();
        }
    }
    request.open("POST", window.location+ "/changecolor",);
    request.setRequestHeader("Content-Type", "application/json")
    request.send(JSON.stringify(colors));

}