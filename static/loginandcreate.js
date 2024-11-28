const delay = ms => new Promise(res => setTimeout(res, ms));

const blink = async () =>{
    let fro = "Fromance"
    let headline = document.getElementById("headline");
    headline.innerText = "Experience"
    for (let char of fro) {
        await delay(500);
        headline.innerText += " " +char
    }
}

window.onload = (event) => {
    blink();
};