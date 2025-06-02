import path from 'path';
import TerserPlugin from 'terser-webpack-plugin';
import { BundleAnalyzerPlugin } from 'webpack-bundle-analyzer';
import MiniCssExtractPlugin from 'mini-css-extract-plugin';
import CssMinimizerPlugin from 'css-minimizer-webpack-plugin';
import CopyWebpackPlugin from 'copy-webpack-plugin';

export default (env, argv) => {
  const isDevelopment = argv.mode === 'development';
  const isAnalyze = env && env.analyze;
  
  // Set output directory
  const outputDir = path.resolve(process.cwd(), 'app/Nydia Extension/Resources');

  return {
    entry: {
      core: './src/core.ts',
      injector: './src/injector.ts',
      background: './src/background.ts',
      dispatcher: './src/dispatcher.ts',
      menu: {
        import: [
          './src/menu.ts',
          './src/settings.ts',
          './src/styles/main.css'
        ],
      },
      popup: './src/popup.ts'
    },
    module: {
      rules: [
        {
          test: /\.ts$/,
          use: [
            {
              loader: 'ts-loader',
              options: {
                transpileOnly: true,
                compilerOptions: {
                  module: 'esnext',
                },
              },
            },
          ],
          exclude: /node_modules/,
        },
        {
          test: /\.css$/,
          use: [
            MiniCssExtractPlugin.loader,
            {
              loader: 'css-loader',
              options: {
                import: true,
                importLoaders: 1,
              }
            },
          ],
        },
      ],
    },
    resolve: {
      extensions: ['.ts', '.css'],
    },
    output: {
      filename: '[name].js',
      path: outputDir,
    },
    plugins: [
      // Modify MiniCssExtractPlugin to create popup.css and menu.css
      new MiniCssExtractPlugin({
        filename: ({ chunk }) => {
          return chunk.name === 'popup' ? 'popup.css' : 'menu.css';
        },
      }),
      // Copy all files from assets
      new CopyWebpackPlugin({
        patterns: [
          {
            from: 'assets',
            to: ''
          }
        ],
      }),
      ...(isAnalyze ? [new BundleAnalyzerPlugin()] : []),
    ],
    optimization: {
      usedExports: true,
      minimize: argv.mode === 'production',
      minimizer: [
        new TerserPlugin({
          extractComments: false,
          terserOptions: {
            format: {
              comments: false,
            },
          },
        }),
        new CssMinimizerPlugin(),
      ],
    },
    mode: isDevelopment ? 'development' : 'production',
    devtool: isDevelopment ? 'inline-source-map' : false,
    watch: isDevelopment,
    watchOptions: {
      ignored: /node_modules/,
    },
  };
};