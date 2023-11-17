import requests
from cdm.wks import PsshExtractor, get_keys_cdrm_api
# HBOMAX Test
def parse_command_line_arguments():
    """Parse command line arguments."""
    parser = __import__('argparse').ArgumentParser(description="Decrypt Widevine content using MPD URL and License URL")
    parser.add_argument("-mpd", required=True, help="URL of the MPD manifest")
    parser.add_argument("-lic", required=True, help="URL of the license server")
    return parser.parse_args()

def get_mpd_response(mpd_url):
    """Get MPD manifest response."""
    mpd_headers = {
        'origin': 'https://play.hbomax.com',
        'referer': 'https://play.hbomax.com/',
    }
    return requests.get(mpd_url, headers=mpd_headers)

def get_license_headers(token):
    """Get headers for the license server request."""
    return {
        'accept': "*/*", # no delet
        'content-length': "316", # no delet
        'Connection': 'keep-alive', # no delet
        'authorization': f'Bearer {token}',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (Ktesttemp, like Gecko) Chrome/90.0.4430.85 Safari/537.36'
    }

def main():
    # Parse command line arguments
    args = parse_command_line_arguments()
    mpd_url, license_url = args.mpd, args.lic

    # Get MPD response
    mpd_response = get_mpd_response(mpd_url)

    # Extract PSSH value from MPD response
    pssh_extractor = PsshExtractor(mpd_response.text)
    pssh_value = pssh_extractor.extract_pssh()

    print("PSSH value:", pssh_value)

    # Get headers for the license server request
    token = ""
  # Update with your actual token
    license_headers = get_license_headers(token)

    # Call the function in keys.py to get the keys
    keys = get_keys_cdrm_api(license_headers, license_url, pssh_value)

    # Process each key
    for key in keys:
        print(f'KEY: {key}')

if __name__ == "__main__":
    main()
