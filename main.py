import argparse
from cdm.wks import WvDecrypt, device_android_generic, PsshExtractor, KeyExtractor
import requests

def get_keys_license(mpd_url, license_url):
    response = requests.get(mpd_url)
    pssh_extractor = PsshExtractor(response.text)
    pssh_value = pssh_extractor.extract_pssh()

    print("PSSH value:", pssh_value)

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
    }

    cert_b64 = None
    key_extractor = KeyExtractor(pssh_value, cert_b64, license_url, headers)
    keys = key_extractor.get_keys()
    wvdecrypt = WvDecrypt(init_data_b64=pssh_value, cert_data_b64=cert_b64, device=device_android_generic)
    raw_challenge = wvdecrypt.get_challenge()
    data = raw_challenge

    return keys

def main():
    parser = argparse.ArgumentParser(description="Decrypt Widevine content using MPD URL and License URL")
    parser.add_argument("-mpd", required=True, help="URL of the MPD manifest")
    parser.add_argument("-lic", required=True, help="URL of the license server")
    args = parser.parse_args()

    mpd_url = args.mpd
    license_url = args.lic

    keys = get_keys_license(mpd_url, license_url)

    for key in keys:
        if isinstance(key, list):
            if key:
                for key_str in key:
                    print(f"KEY: {key_str}")

if __name__ == "__main__":
    main()
