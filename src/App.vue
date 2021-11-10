<template>
  <div>
    <div id="app">
      <router-view/>
    </div>
    <div class="back-top" @click="backTop" v-if="showBackTop">
      <img src="./assets/img/top.png" />
    </div>
  </div>
</template>

<script>
// import Lazyload from 'vant/lib/lazyload';
export default {
  data() {
    return {
      showBackTop: false,
    };
  },
  methods: {
    backTop() {
      window.app.scrollIntoView();
    },
  },
  mounted() {
    window.onscroll = () => {
      if (window.scrollY > 300) {
        this.showBackTop = true;
      } else {
        this.showBackTop = false;
      }
    };
  },
};
</script>

<style>
@import url('./assets/css/font.css');
html, body {
  margin: 0;
  padding: 0;
}
.back-top{
  position: fixed;
  bottom: 24px;
  right: 24px;
  height: 84px;
  width: 84px;
}
</style>
