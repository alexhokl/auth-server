const post = (url, data) => {
    return fetch(url, {
        method: 'post',
        headers: {
            "Content-type": "application/json"
        },
        body: JSON.stringify(data),
    })
    .then(checkSuccessResponse);
};

const patch = (url, data) => {
    return fetch(url, {
        method: 'patch',
        headers: {
            "Content-type": "application/json"
        },
        body: JSON.stringify(data),
    })
    .then(checkSuccessResponse);
};

const get = (url) => {
    return fetch(url, {
        method: 'get',
    })
    .then(checkSuccessResponse);
};

const parseJsonResponse = response => response.json();

const checkSuccessResponse = response =>
    response.status >= 200 && response.status < 300
        ? Promise.resolve(response)
        : Promise.reject(new Error(response.statusText));

const base64UrlEncode = str =>
  btoa(String.fromCharCode.apply(null, new Uint8Array(str)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
