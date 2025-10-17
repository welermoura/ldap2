const path = require('path');

module.exports = {
  entry: './static/js/src/index.js', // Nosso arquivo de entrada React
  output: {
    path: path.resolve(__dirname, 'static/js/dist'), // Onde o arquivo compilado será salvo
    filename: 'bundle.js' // O nome do arquivo de saída
  },
  module: {
    rules: [
      {
        test: /\.(js|jsx)$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-env', '@babel/preset-react']
          }
        }
      }
    ]
  },
  resolve: {
    extensions: ['.js', '.jsx']
  }
};