const newPasswordInput = document.getElementById('new-password');
const toggleNewPasswordButton = document.getElementById('toggle-new-password');

const toggleNewPassword = () => {
  if (newPasswordInput.type === 'password') {
    newPasswordInput.type = 'text';
    toggleNewPasswordButton.textContent = 'Hide password';
    toggleNewPasswordButton.setAttribute('aria-label',
      'Hide password.');
  } else {
    newPasswordInput.type = 'password';
    toggleNewPasswordButton.textContent = 'Show password';
    toggleNewPasswordButton.setAttribute('aria-label',
      'Show password as plain text. ' +
      'Warning: this will display your password on the screen.');
  }
}

toggleNewPasswordButton.addEventListener('click', toggleNewPassword);
