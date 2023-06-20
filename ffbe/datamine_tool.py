import base64
import json
import os
import xml.etree.ElementTree as ET

from Crypto.Cipher import AES

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


class FFBEDatamineTool(object):
    def __init__(self, in_folder: str, out_folder: str):
        super().__init__()

        self.__in_folder = in_folder
        self.__out_folder = out_folder

        self.__parse_gamedata()

    def __parse_gamedata(self):
        gamedata_path = os.path.join(self.__in_folder, "gamedata.xml")

        root = ET.parse(gamedata_path).getroot()

        self.__gamedata = dict()

        for child in root:
            name = child.attrib['name'][3:]
            value = child.text
            self.__gamedata[name] = value

    def __decrypt_with_fixed_key(self, data, key):
        key = key.encode("utf-8")
        key = key.ljust(16, b'\0')[:16]

        iv = b"dZMjkk8gFDzKHlsx"
        aes = AES.new(key, AES.MODE_CBC, iv)
        encrypted_bytes = base64.b64decode(data)
        decrypted_bytes = aes.decrypt(encrypted_bytes)
        decrypted_text = self.__remove_custom_padding(decrypted_bytes).decode("utf-8")

        return decrypted_text

    def __remove_custom_padding(self, data):
        padding_length = data[-1]
        padding_value = data[-padding_length:]

        for byte in padding_value:
            if byte != padding_length:
                raise ValueError("Padding is incorrect.")

        return data[:-padding_length]

    @property
    def gamedata(self):
        return self.__gamedata

    @property
    def in_folder(self):
        return self.__in_folder

    @property
    def out_folder(self):
        return self.__out_folder

    def decode_file(self, file_path, key):
        with open(file_path, "r") as dat_file:
            dat_content = dat_file.read()
            dat_lines = dat_content.splitlines()
            entire_file = []

            for base64_str in dat_lines:
                decrypted_mst = self.__decrypt_with_fixed_key(base64_str, key)
                decrypted_entries = decrypted_mst.splitlines()
                entire_file.extend(decrypted_entries)

        return [item for item in map(self.json_to_dict, entire_file) if item is not None]

    def json_to_dict(self, data: str):
        last_bracket_index = data.rfind('}')

        if last_bracket_index != -1:
            cleaned_string = data[:last_bracket_index + 1]
        else:
            cleaned_string = data

        return self.parse_key_names(json.loads(cleaned_string)) if cleaned_string else None

    def parse_key_names(self, decoded_data: dict):
        with open(os.path.join(_DATA_DIR, "variables.json"), "r") as f:
            keys_map = json.load(f)

        parsed_dict = dict()
        for k, v in decoded_data.items():
            if k in keys_map:
                parsed_key = keys_map[k]
                parsed_dict[parsed_key] = v
            else:
                parsed_dict[k] = v

        return parsed_dict

    def decode_all_files(self):
        with open(os.path.join(_DATA_DIR, "files.json"), "r") as f:
            files = json.load(f)

        decode_files = dict()
        for mst_file, v in files.items():
            file_ver = self.gamedata.get(mst_file)
            name = v["Name"]
            key = v["Key"]

            if file_ver:
                data_filename = f"Ver{file_ver}_{name}.dat"
                file_path = os.path.join(self.__in_folder, data_filename)
                if os.path.isfile(file_path):
                    decode_files[mst_file] = self.decode_file(file_path, key)

        self.save_to_file(decode_files)

    def save_to_file(self, decode_files: dict):
        for file, data in decode_files.items():
            file_path = os.path.join(self.out_folder, f"{file}.json")
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
