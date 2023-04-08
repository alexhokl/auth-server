const post = async (url, data) => {
    const response = await fetch(url, {
        method: 'POST',
        headers: {
            "Content-type": "application/json"
        },
        body: JSON.stringify(data),
    });
    return checkSuccessResponse(response);
};

const patch = async (url, id, data) => {
    const response = await fetch(`${url}/${id}`, {
        method: 'PATCH',
        headers: {
            "Content-type": "application/json"
        },
        body: JSON.stringify(data),
    });
    return checkSuccessResponse(response);
};

const get = async (url) => {
    const response = await fetch(url, {
        method: 'GET',
    });
    return checkSuccessResponse(response);
};

const deleteResource = async (url, id) => {
    const response = await fetch(`${url}/${id}`, {
        method: 'delete',
    });
    return checkSuccessResponse(response);
};

const parseJsonResponse = async response => response.json();

const checkSuccessResponse = response =>
    response.status >= 200 && response.status < 300
        ? Promise.resolve(response)
        : Promise.reject(new Error(response.statusText));

const base64UrlEncode = arrayBuf =>
  base64ToBase64Url(btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuf))));

const base64UrlDecode = str =>
  Uint8Array.from(atob(base64UrlToBase64(str)), c => c.charCodeAt(0));

const base64ToBase64Url = str =>
  str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const base64UrlToBase64 = str =>
  str.replace(/\-/g, '+').replace(/\_/g, '/').concat('=');
