"""
Azure Function HTTP trigger that serves as an AiTM (Adversary-in-the-Middle) detector.
This function inspects the 'Referer' header of incoming HTTP GET requests to determine if the request originates from a trusted Microsoft authentication or Office 365 domain. If the referer is missing or does not match any of the predefined valid referers, it returns a warning image. Otherwise, it returns a 200 OK response without content.
Routes:
    - /aitmdetector [GET]: Main endpoint for referer validation.
Args:
    req (func.HttpRequest): The incoming HTTP request object.
Returns:
    func.HttpResponse: 
        - If the referer is invalid or missing, returns a warning image (image/png).
        - If the referer is valid, returns a 200 OK response with no content.
        - In case of exceptions, returns a 200 OK response.
"""
import azure.functions as func
import logging
import os

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="aitmdetector", methods=["GET"])
def aitmdetector(req: func.HttpRequest) -> func.HttpResponse:
    try:
        logging.info('Processing HTTP request.')
        valid_referers = [
            'https://login.microsoftonline.com/',
            'https://login.microsoft.com/',
            'https://login.microsoft.net/',
            'https://autologon.microsoftazuread-sso.com/',
            'https://tasks.office.com/',
            'https://outlook.office.com/',
            'https://login.windows.net/'
        ]

        bad_image_path  = os.path.join(os.path.dirname(__file__), 'static', 'Warning.png')
        referer         = req.headers.get('referer')

        if referer is None or not any(valid in referer for valid in valid_referers):
            logging.info(f"Bad or missing referer: {referer}")
            with open(bad_image_path, 'rb') as f:
                image_data = f.read()

            return func.HttpResponse(
                body=image_data,
                status_code=200,
                mimetype='image/png'
            )
        else:
            logging.info(f"Valid referer: {referer}")
            return func.HttpResponse(status_code=200)
    except Exception as e:
        logging.error(f"Error processing request: {e}")
        return func.HttpResponse(status_code=200)