from ffbe.datamine_tool import FFBEDatamineTool

if __name__ == "__main__":
    ffbe = FFBEDatamineTool("in", "out")
    ffbe.decode_all_files()
