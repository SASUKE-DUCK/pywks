import argparse
import requests
from cdm.wks import PsshExtractor, get_keys_license_cdrm_project, print_keys_cdrm_project

token = ""

def main():
    parser = argparse.ArgumentParser(description="Decrypt Widevine content using MPD URL and License URL")
    parser.add_argument("-mpd", required=True, help="URL of the MPD manifest")
    parser.add_argument("-lic", required=True, help="URL of the license server")
    args = parser.parse_args()

    mpd_url = args.mpd
    license_url = args.lic

    headers_mpd = {
        'origin': 'https://play.hbomax.com',
        'referer': 'https://play.hbomax.com/',
    }

    response = requests.get(mpd_url, headers=headers_mpd)
    pssh_extractor = PsshExtractor(response.text)
    pssh_value = pssh_extractor.extract_pssh()

    print("PSSH value:", pssh_value)

    headers_license = {
        'authorization': f'Bearer {token}',
    }

    response = get_keys_license_cdrm_project(license_url, headers_license, pssh_value)
    print_keys_cdrm_project(response)

if __name__ == "__main__":
    main()
