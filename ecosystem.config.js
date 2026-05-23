module.exports = {
  apps: [
    {
      name: 'cipherx-node',
      script: './target/release/cipherx-node', // was debug — now release
      cwd: '/root/cipherx',
      interpreter: 'none',
      env: {
        RUST_LOG: 'info',
        // This machine IS the seed node (141.11.243.5:9152).
        // Setting CIPHERX_PUBLIC_IP prevents the node from dialing itself.
        CIPHERX_PUBLIC_IP: '141.11.243.5',
        // To override seed list: CIPHERX_SEED_NODES: 'ip1:9152,ip2:9152'
      },
      out_file: './logs/cipherx-out.log',
      error_file: './logs/cipherx-err.log',
      merge_logs: false,
      log_date_format: 'YYYY-MM-DD HH:mm:ss',
      autorestart: true,
      restart_delay: 5000,
      max_restarts: 10,
    },
    {
      name: 'cipherx-bot',
      script: '/root/cipherx_bot.py',
      cwd: '/root',
      interpreter: '/usr/bin/python3',
      env: {
        CIPHERX_BOT_TOKEN: '8655819263:AAElFoZuM9vo1wr-s0UIbpqnlHacD_9GjdU',
        CIPHERX_ACCESS_CODE: 'cipher31',
      },
      out_file: '/root/logs/cipherx-bot-out.log',
      error_file: '/root/logs/cipherx-bot-err.log',
      merge_logs: false,
      log_date_format: 'YYYY-MM-DD HH:mm:ss',
      autorestart: true,
      restart_delay: 5000,
      max_restarts: 10,
    },
  ],
};
