# chmod +x build.sh

if [ -d "build" ]; then
    echo "build klasörü mevcut, içeriği temizleniyor..."
    sudo rm -rf build/*
else
    echo "build klasörü yok, oluşturuluyor..."
    mkdir build
fi

cd build || { echo "build klasörüne geçilemedi!"; exit 1; }

echo "CMake yapılandırması başlatılıyor..."
cmake ..

echo "Derleme başlatılıyor..."
make

echo "Derleme tamamlandı."