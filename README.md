<div id="top"></div>
<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Don't forget to give the project a star!
*** Thanks again! Now go create something AMAZING! :D
-->



<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]



<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/gobblegoob/lowimpactplus">
    <!--<img src="images/logo.png" alt="Logo" width="80" height="80">-->
  </a>

<h3 align="center">lowimpactplus</h3>

  <p align="center">
    Analyze RADIUS reports for a concise list of wired endpoints hitting specified catch-all policies
    <br />
    <!--<a href="https://github.com/gobblegoob/lowimpactplus"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/gobblegoob/lowimpactplus">View Demo</a>-->
    ·
    <a href="https://github.com/gobblegoob/lowimpactplus/issues">Report Bug</a>
    ·
    <a href="https://github.com/gobblegoob/lowimpactplus/issues">Request Feature</a>
  </p>
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project
Helps you move toward full wired enforcement by identifying endpoints that are hitting a catch-all permit policy.  This phase may be referred to as Low Impact, and helps administrators pushing 802.1x out to their switch ports avoid accidently denying access to an endpoint that has no relevant authorization policy yet.  Often, this is a MAB authorization policy at the bottom of your policy list that will simply permit access to all endpoints.
    
This script ingests a .csv RADIUS Authentications report from Cisco ISE.  It deduplicates and weeds out endpoints that are no longer hitting Low Impact catch-all policies.  You are left with a csv file listing only the hosts that are hitting the low impact policy.  This makes it easy to get a count of endpoints you need to address before you disable your catch-all policy, moving into your final enforcement plan.
<!--[![Product Name Screen Shot][product-screenshot]](https://example.com)-->

<!--Here's a blank template to get started: To avoid retyping too much info. Do a search and replace with your text editor for the following: `gobblegoob`, `lowimpactplus`, `twitter_handle`, `linkedin_username`, `email_client`, `email`, `lowimpactplus`, `project_description`-->


<p align="right">(<a href="#top">back to top</a>)</p>



### Built With
* [Python 3.9](https://www.python.org/)
<!--
* [Next.js](https://nextjs.org/)
* [React.js](https://reactjs.org/)
* [Vue.js](https://vuejs.org/)
* [Angular](https://angular.io/)
* [Svelte](https://svelte.dev/)
* [Laravel](https://laravel.com)
* [Bootstrap](https://getbootstrap.com)
* [JQuery](https://jquery.com)

<p align="right">(<a href="#top">back to top</a>)</p>
-->


<!-- GETTING STARTED -->
## Getting Started

Dependencies:
 - pandas => 1.3.4

<!--
### Prerequisites

This is an example of how to list things you need to use the software and how to install them.
* npm
  ```sh
  npm install npm@latest -g
  ```
-->
### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/gobblegoob/lowimpactplus.git
   ```
2. Install the requirements
  ```sh
  pip install -r requirements.txt
  ```
  
<p align="right">(<a href="#top">back to top</a>)</p>



<!-- USAGE EXAMPLES -->

## Usage

In brief: 
1. Modify the script variables to match your targeted policies.
    - Edit the src_report variable to match the RADIUS report csv file you wish to analyze
<img src="/images/srcreport.png" alt="src_report">
    - This is done by editing the li_policy_list list variable to reflect your designated low impact policies.
<img src="/images/lipolicylist.png" alt="li_policy_list">
2. Export a 30 Day RADIUS Authentication report as a csv file to your selected repository. This will give you the most complete report
3. Save the report csv file to the lowimpact plus directory 
4. Execute the script
  ```sh
  python3 lowimpactplus.py
  ```
5. Use the output file to help you identify and remediate endpoints found

<p align="right">(<a href="#top">back to top</a>)</p>


<!-- ROADMAP -->
## Roadmap

- [ ] Add arguments to set input file
- [ ] Add gui to select input file


See the [open issues](https://github.com/gobblegoob/lowimpactplus/issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- CONTRIBUTING -->
  <!--
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#top">back to top</a>)</p>


-->
<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- CONTACT -->
## Contact


Project Link: [https://github.com/gobblegoob/lowimpactplus](https://github.com/gobblegoob/lowimpactplus)

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- ACKNOWLEDGMENTS -->
<!--
## Acknowledgments

* []()
* []()
* []()

<p align="right">(<a href="#top">back to top</a>)</p>
-->


<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/gobblegoob/lowimpactplus.svg?style=for-the-badge
[contributors-url]: https://github.com/gobblegoob/lowimpactplus/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/gobblegoob/lowimpactplus.svg?style=for-the-badge
[forks-url]: https://github.com/gobblegoob/lowimpactplus/network/members
[stars-shield]: https://img.shields.io/github/stars/gobblegoob/lowimpactplus.svg?style=for-the-badge
[stars-url]: https://github.com/gobblegoob/lowimpactplus/stargazers
[issues-shield]: https://img.shields.io/github/issues/gobblegoob/lowimpactplus.svg?style=for-the-badge
[issues-url]: https://github.com/gobblegoob/lowimpactplus/issues
[license-shield]: https://img.shields.io/github/license/gobblegoob/lowimpactplus.svg?style=for-the-badge
[license-url]: https://github.com/gobblegoob/lowimpactplus/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/linkedin_username
[product-screenshot]: images/screenshot.png
