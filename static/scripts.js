var password = document.getElementById("password")
  , confirm_password = document.getElementById("repassword");
  
var email = document.getElementById("email")
  , confirm_email = document.getElementById("remail");
  

function formValidationRegister()  
{ 
validatePassword();
validateEmail();
}

function validatePassword(){
  if(password.value != confirm_password.value) {
    confirm_password.setCustomValidity("Passwords Don't Match");
  } else {
    confirm_password.setCustomValidity('');
}

password.onchange = validatePassword;
confirm_password.onkeyup = validatePassword;
}

function validateEmail(){
  if(email.value != confirm_email.value) {
    confirm_email.setCustomValidity("Email IDs Don't Match");
  } else {
    confirm_email.setCustomValidity('');
}

email.onchange = validateEmail;
confirm_email.onkeyup = validateEmail;
}