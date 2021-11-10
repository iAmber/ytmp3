<template>
  <div class="home" :class="[isMobile? 'mobile' : 'pc', mode]">
    <div class="title">
      <div class="home-btn" @click="refresh">HOME</div>
      <div class="theme-btn" @click="changeTheme">THEME[DARK]</div>
    </div>
    <img v-if="isMobile" class="logo" src="../assets/img/logo200x50.png" />
    <img v-else class="logo" src="../assets/img/logo240x60.png" />
    <div class="rank-title">🔥 Top 10 Chart 🔥</div>
    <div class="rank-list">
      <div
        v-for="(item, index) in list"
        :key="index"
        class="rank-item"
      >
        <div class="rank-index">No.{{index + 1}}</div>
        <div class="rank-video">
          <youtube :video-id="item.key" ref="youtube" @playing="playing" @click="playVideo" />
        </div>
        <div class="desc">
          <div class="desc-left">
            <div class="desc-title">{{item.title}}</div>
            <div class="desc-score">{{item.score}}K views</div>
          </div>
          <div class="desc-right">
            <img class="copy-btn"
            src="../assets/img/copy.png"
            :data-clipboard-text="item.url"
            @click="copyUrl($event,item.url)" />
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios';
import Clipboard from 'clipboard';

export default {
  name: 'Home',
  data() {
    return {
      list: [],
      country: '',
      mode: 'light',
      ipList: [
        'https://154.82.111.45.nip.io',
        'https://154.82.111.41.sslip.io',
        'https://154.82.111.42.sslip.io',
        'https://154.82.111.111.sslip.io',
        'https://154.82.111.112.sslip.io',
        'https://154.82.111.113.sslip.io',
        'https://154.82.111.116.sslip.io',
        'https://154.82.111.99.sslip.io',
        'https://154.82.111.77.sslip.io',
      ],
    };
  },
  components: {
  },
  computed: {
    player() {
      return this.$refs.youtube.player;
    },
  },
  async mounted() {
    await this.getCountryCode();
    this.getList();
  },
  methods: {
    playVideo() {
      this.player.playVideo();
    },
    playing() {
      console.log('we are watching!!!');
    },
    refresh() {
      this.$router.go(0);
    },
    async getCountryCode() {
      const url = 'https://ads-website.ytsservice.com/ads/address/country';
      const { data, status } = await axios.get(url);
      if (status === 200) {
        this.country = data?.data?.country;
      }
    },
    async getList() {
      const ip = this.getRandomIp();
      const url = `${ip}/rank/${this.country}`;
      const { data, status } = await axios.get(url);
      if (status === 200) {
        this.list = data?.map((item) => ({
          ...item,
          // eslint-disable-next-line prefer-template
          url: 'https://www.youtube.com/watch?v=' + item.key,
        })).slice(0, 12);
      }
    },
    getRandomIp() {
      const len = this.ipList.length;
      const index = Math.floor((Math.random() * len));
      return this.ipList[index];
    },
    changeTheme() {
      this.mode = 'dark';
    },
    copyUrl() {
      const clipboard = new Clipboard('.copy-btn');
      clipboard.on('success', () => {
        console.log('复制成功');
        clipboard.destroy(); // 释放内存
      });
      clipboard.on('error', () => {
        console.log('不支持复制,该浏览器不支持自动复制');
        clipboard.destroy(); // 释放内存
      });
    },
  },
};

</script>
<style>
.home.dark {
  background-color: red;
}
.title{
  height: 40px;
  display: flex;
  justify-content: center;
  align-items: center;
  color: #0287CF;
  font-family: Roboto-Regular;
  font-size: 14px;
  font-weight: 400;
}
.title .home-btn {
  margin-right: 20px;
  cursor: pointer;
  -webkit-tap-highlight-color: rgba(0, 0, 0, 0);
}
.title .theme-btn {
  margin-right: 20px;
  cursor: pointer;
  -webkit-tap-highlight-color: rgba(0, 0, 0, 0);
}
.logo {
  display: flex;
  margin: 32px auto;
  width: 200px;
}
.rank-title {
  font-family: Roboto-Bold;
  font-size: 28px;
  color: #000000;
  text-align: center;
  line-height: 32px;
  font-weight: 400;
  margin-bottom: 36px;
}
.rank-item {
  position: relative;;
  margin: 0 24px 32.23px;
  background: rgba(206,206,206,0.09);
  border: 1px solid #F5F5F5;
  border-radius: 10px;
}
.rank-item .desc{
  display: flex;
  padding: 0 12px;
  width: 100%;
  box-sizing: border-box;
  justify-content: space-between;
  align-items: center;
}

.rank-item .rank-index {
  position: absolute;
  left: -7px;
  top: -8px;
  width: 72px;
  height: 36px;
  line-height: 36px;
  text-align: center;
  background: #0287CF;
  border-radius: 2px;
  font-family: Roboto-Medium;
  font-size: 16px;
  color: #FFFFFF;
  text-align: center;
  font-weight: 500;
  z-index: 9999;
}
.rank-item .rank-video {
  height: 176px;
}
.rank-item .rank-video iframe {
  width: 100%;
  height: 176px;
}

.rank-item .desc .desc-left{
  max-width: calc(100% - 36px);
  overflow-x: hidden;
}
.rank-item .desc .desc-title {
  font-family: Roboto-Bold;
  font-size: 14px;
  color: #000000;
  line-height: 18px;
  font-weight: 700;
  margin-top: 12px;
  margin-bottom: 4px;
  height: 18px;
  overflow: hidden;
}

.rank-item .desc .desc-score {
  font-family: Roboto-Regular;
  font-size: 12px;
  color: #979494;
  line-height: 16px;
  font-weight: 400;
  margin-bottom: 12px;
}

.rank-item .desc .desc-right {
  display: flex;
  align-items: center;
}

.rank-item .desc .copy-btn {
  width: 24px;
  height: 24px;
  cursor: pointer;
}

.pc .title {
  height: 60px;
  margin-bottom: 32px;
}
.pc .logo {
  width: 240px;
  margin: 30px auto 32px;
}
.pc .rank-title {
  margin-bottom: 40px;
}
.pc .rank-item .desc .desc-title {
  margin-top: 8px;
}
.pc .rank-list{
  display: flex;
  width: 940px;
  margin-left: auto;
  margin-right: auto;
  flex-wrap: wrap;
}
.pc .rank-item {
  margin-left: 0;
  margin-right: 20px;
  width: 220px;
  box-sizing: border-box;
}
.pc .rank-video {
  height: 124px;
}
.pc .rank-video iframe {
  width: 220px;
  height: 124px;
}
.pc .rank-item:nth-child(4n){
  margin-right: 0;
}

</style>
