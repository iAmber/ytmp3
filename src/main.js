import Vue from 'vue';
import App from './App.vue';
import router from './router';

// 判断浏览器函数
function isMobile() {
  if (window.navigator.userAgent.match(/(phone|pad|pod|iPhone|iPod|ios|iPad|Android|Mobile|BlackBerry|IEMobile|MQQBrowser|JUC|Fennec|wOSBrowser|BrowserNG|WebOS|Symbian|Windows Phone)/i)) {
    return true; // 移动端
  }
  return false; // PC端
}

Vue.config.productionTip = false;
Vue.prototype.isMobile = isMobile();

new Vue({
  router,
  render: (h) => h(App),
}).$mount('#app');
