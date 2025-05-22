# AITM Detector – Azure Function

This Azure Function implements a lightweight **Adversary-in-the-Middle (AiTM) detection mechanism** by validating the `Referer` header of incoming HTTP requests. If the referer does not originate from a trusted Microsoft domain, the function returns a warning image—providing a simple but effective early warning against suspicious or potentially phishing-related activity.

> ⚠️ **Disclaimer**  
> This method only detects **direct-proxy AiTM phishing attacks**. It does **not** defend against **indirect-proxy phishing kits** (commonly used in phishing-as-a-service platforms), which often bypass or suppress client-side modifications such as `CustomCSS`.  
> This solution should be viewed as a **supplementary signal** within a broader, layered phishing detection and prevention strategy.
 **Potential evasion techniques** include the manipulation of referers, and while this is a straightforward detection method, it can be bypassed in more advanced attacks.
 
> Read more on potential evasion techniques:  
> [Clipping the Canary’s Wings – Bypassing AiTM Phishing Detections](https://insights.spotit.be/2024/06/03/clipping-the-canarys-wings-bypassing-aitm-phishing-detections/)

> Designed for deployment on **Azure Function Apps (Flex Consumption Plan)**.

---

### Video Explanation

For a deeper understanding of how the AiTM detector works and its effectiveness, check out the full explanation on my YouTube channel:

[YouTube video](https://youtu.be/hd2ueDxTWNU)

---

### Acknowledgements

This approach was originally proposed by **[Attic Security by Zolder](https://atticsecurity.com/en/aitm/)**, who offer advanced hosted versions with additional protections and support.

Special thanks to:
- **[Matt Kiely](https://github.com/HuskyHacks)** and **[Kelvin Tegelaar](https://github.com/KelvinTegelaar)** for their contributions to the open-source implementation under **Clarion** and the integration to **CIPP**.
  - 🔗 [Clarion](https://github.com/HuskyHacks/clarion)
  - 🔗 [CIPP](https://cipp.app/)

---

## Function Overview

- **Route**: `/api/aitmdetector`
- **Trigger Type**: `HTTP` (Anonymous access)
- **Behavior**:
  - ✅ Returns `200 OK` (empty response) for requests with valid Microsoft referers
  - ⚠️ Returns `200 OK` with a warning image if the referer is missing or does not match trusted domains

---

## Trusted Referer Domains

The function determines trust based on whether the incoming `Referer` header contains **any** of the following Microsoft-owned domains:

```python
valid_referers = [
        'https://login.microsoftonline.com/',
        'https://login.microsoft.com/',
        'https://login.microsoft.net/',
        'https://autologon.microsoftazuread-sso.com/',
        'https://tasks.office.com/',
        'https://outlook.office.com/',
        'https://login.windows.net/'
    ]
```

## Custom CSS File

To apply a visual warning on the sign-in page, create a file named `extsignin.css` with the following content:

```css
.ext-sign-in-box {
    background-image: url(https://<your-function-url>);
}
```

### References:
  - 🔗 [How to apply custom branding](https://learn.microsoft.com/en-us/entra/fundamentals/how-to-customize-branding)
  - 🔗 [Direct link to apply Custom CSS](https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/CompanyBrandingOverview.ReactView)