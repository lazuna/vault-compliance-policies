> ls
lynis-3.0.8.tar.gz

> tar -xvf lynis-3.0.8.tar.gz
> cd lynis
> sudo chown -R ./*

> ./lynis audit system > ./report.txt
> more ./report.txt
