import argparse
from cdm.wks import KeyExtractor, DataExtractor_DSNP
import requests
token = ""
def get_keys_license(m3u8_url):
    response = requests.get(m3u8_url)
    content = response.text if response.status_code == 200 else None

    data_extractor = DataExtractor_DSNP(content)

    if content:
        characteristics_list = data_extractor.get_characteristics_list()

        if characteristics_list:
            print("Choose CHARACTERISTICS Value:")
            for i, (characteristics, _) in enumerate(characteristics_list):
                print(f"{i + 1}. {characteristics}")

            choice = int(input("Enter the number of the CHARACTERISTICS you want: "))
            characteristics, base64_data = data_extractor.extract_base64_by_choice(choice)

            if characteristics and base64_data:
                print("CHARACTERISTICS Value:", characteristics)

    print("PSSH value (Base64 Data):", base64_data)

    license_url = "https://disney.playback.edge.bamgrid.com/widevine/v1/obtain-license"
    
    headers = {
        'authorization': f'Bearer {token}',
        'origin': 'https://www.disneyplus.com',
        'referer': 'https://www.disneyplus.com/',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
    }

    cert_b64 = None
    key_extractor = KeyExtractor(base64_data, cert_b64, license_url, headers)
    keys = key_extractor.get_keys()

    for key in keys:
        if isinstance(key, list):
            if key:
                for key_str in key:
                    print(f"KEY: {key_str}")

    return base64_data

def main():
    parser = argparse.ArgumentParser(description="Decrypt Widevine content using M3U8 URL")
    parser.add_argument("-m3u8", required=True, help="URL of the M3U8 manifest")
    args = parser.parse_args()

    m3u8_url = args.m3u8

    pssh_value = get_keys_license(m3u8_url)

if __name__ == "__main__":
    main()
