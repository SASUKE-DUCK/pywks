import argparse
import requests
from cdm.wks import PsshExtractor, get_keys_cache_cdrm_project

def extract_pssh_value(mpd_url):
    headers_mpd = {
        'origin': 'https://play.hbomax.com',
        'referer': 'https://play.hbomax.com/',
    }

    response = requests.get(mpd_url, headers=headers_mpd)

    if response.status_code == 200:
        pssh_extractor = PsshExtractor(response.text)
        pssh_value = pssh_extractor.extract_pssh()
        return pssh_value
    else:
        raise ValueError(f"Error: Unable to fetch MPD manifest, Status Code: {response.status_code}")

def main():
    parser = argparse.ArgumentParser(description="Decrypt Widevine content using MPD URL and License URL")
    parser.add_argument("-mpd", required=True, help="URL of the MPD manifest")
    args = parser.parse_args()

    mpd_url = args.mpd

    try:
        pssh_value = extract_pssh_value(mpd_url)
        print("PSSH value:", pssh_value)
        get_keys_cache_cdrm_project(pssh_value)
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
