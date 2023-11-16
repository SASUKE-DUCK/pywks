from cdm.wks import WvDecrypt, device_android_generic, extract_pssh_m3u8, KeyExtractor
import argparse
import requests

def get_keys_license(m3u8_url, license_url):
    response = requests.get(m3u8_url)
    pssh_value = extract_pssh_m3u8(response.text)

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
    parser = argparse.ArgumentParser(description="Decrypt Widevine content using M3U8 URL and License URL")
    parser.add_argument("-m3u8", required=True, help="URL of the M3U8 manifest")
    parser.add_argument("-lic", required=True, help="URL of the license server")
    args = parser.parse_args()

    m3u8_url = args.m3u8
    license_url = args.lic

    keys = get_keys_license(m3u8_url, license_url)

    for key in keys:
        if isinstance(key, list):
            if key:
                for key_str in key:
                    print(f"KEY: {key_str}")

if __name__ == "__main__":
    main()