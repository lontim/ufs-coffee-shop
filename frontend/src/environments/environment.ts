/* @TODO replace with your variables
 * ensure all variables on this page match your project
 */

export const environment = {
  production: false,
  apiServerUrl: 'http://127.0.0.1:5000', // the running FLASK api server url
  auth0: {
    url: 'tim-eu.eu', // the auth0 domain prefix
    audience: 'latte', // the audience set for the auth0 app
    clientId: 'BgbN7s6zbCrpCj6MYlQZVFe1dn03KLTG', // the client id generated for the auth0 app
    callbackURL: 'http://localhost:8100', // the base url of the running ionic application. 
  }
};
