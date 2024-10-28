var Rotation = 0
function rotate(){
    var img = document.getElementById("logo");
    Rotation = Rotation - 90;
    img.style.transform = "rotate("+Rotation.toString()+"deg)";
    console.log("flip");
}

function like_user(user_that_likes,user_that_got_liked) {
    const body = JSON.stringify(
        {
            "user_that_likes": user_that_likes,
            "user_that_got_liked": user_that_got_liked
        }
    );
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/like_user");
    xhr.setRequestHeader("Content-Type", "application/json; charset=UTF-8");
    xhr.onload = () => {
        if (xhr.readyState == 4 && xhr.status == 201) {
          console.log(JSON.parse(xhr.responseText));
        } else {
          console.log(`Error: ${xhr.status}`);
        }
      };
      xhr.send(body);
}

const toggleBtn = document.getElementById('toggle_like');
toggleBtn.addEventListener('click', () => {
  toggleBtn.classList.toggle('active');
});