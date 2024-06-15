// navToggle.js

var navToggle = document.getElementById("nav-toggle");
var nav = document.getElementById("nav");

navToggle.onclick = function () {
  if (navToggle.classList.contains("nav-toggle--open")) {
    navToggle.classList.remove("nav-toggle--open");
  } else {
    navToggle.classList.add("nav-toggle--open");
  }

  if (nav.classList.contains("nav--visible")) {
    nav.classList.remove("nav--visible");
  } else {
    nav.classList.add("nav--visible");
  }
};