import argparse
from cdm.wks import parse_manifest_ism

def main():
    # Create an ArgumentParser object and add the 'urls' argument
    parser = argparse.ArgumentParser(description='Script for parsing Smooth Streaming manifest URLs.')
    parser.add_argument('urls',
                        help='The URLs to parse. You may need to wrap the URLs in double quotes if you have issues.',
                        nargs='+')

    # Parse the arguments
    args = parser.parse_args()

    # Iterate over the provided URLs
    for manifest_link in args.urls:
        kid, stream_info_list, encoded_string = parse_manifest_ism(manifest_link)

        # Print information for each stream
        for stream_info in stream_info_list:
            type_info = stream_info['type']
            codec = stream_info['codec']
            bitrate = stream_info['bitrate']
            resolution = stream_info['resolution']

            if type_info == 'video':
                print(f'[INFO] VIDEO - Codec: {codec}, Resolution: {resolution}, Bitrate: {bitrate}')
            elif type_info == 'audio':
                language = stream_info['language']
                track_id = stream_info['track_id']
                print(f'[INFO] AUDIO - Codec: {codec}, Bitrate: {bitrate}, Language: {language}, Track ID: {track_id}')

        # Print PSSH information
        print('\n[INFO] PSSH:', encoded_string)

if __name__ == "__main__":
    main()