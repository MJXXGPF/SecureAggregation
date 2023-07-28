import os
import zipfile
import shutil



def zip_folder(folder_path, output_path):
    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                if file.endswith('.py'):
                    rel_path = os.path.relpath(file_path, folder_path)
                    zipf.write(file_path, arcname=rel_path)

# 示例用法
folder_path = 'E:\\GraduationProject\\FLCode'  # 替换为要打包的文件夹路径
output_path = 'E:\\GraduationProject\\FLCode\\FLCode.zip'  # 替换为输出的ZIP文件路径

zip_folder(folder_path, output_path)
print('Python files successfully zipped.')


source = 'E:\\GraduationProject\\FLCode\\FLCode.zip'
destination = 'C:\\Users\pengfeigui\Desktop\\FLCode.zip' 
shutil.move(source, destination)


