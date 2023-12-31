const currentPasswordInput = document.getElementById('current-password');
const newPasswordInput = document.getElementById('new-password');
const toggleCurrentPasswordButton = document.getElementById('toggle-current-password');
const toggleNewPasswordButton = document.getElementById('toggle-new-password');

const toggleCurrentPassword = () => {
  if (currentPasswordInput.type === 'password') {
    currentPasswordInput.type = 'text';
    toggleCurrentPasswordButton.textContent = 'Hide password';
    toggleCurrentPasswordButton.setAttribute('aria-label',
      'Hide password.');
  } else {
    currentPasswordInput.type = 'password';
    toggleCurrentPasswordButton.textContent = 'Show password';
    toggleCurrentPasswordButton.setAttribute('aria-label',
      'Show password as plain text. ' +
      'Warning: this will display your password on the screen.');
  }
}

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

toggleCurrentPasswordButton.addEventListener('click', toggleCurrentPassword);
toggleNewPasswordButton.addEventListener('click', toggleNewPassword);
