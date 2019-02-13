Code to go with the blog post (link here when final)
    
    
    ─ Session info ──────────────────────────────────────────────────────────────────────
     setting  value                                 
     version  R version 3.5.2 RC (2018-12-17 r75868)
     os       macOS Mojave 10.14.4                  
     system   x86_64, darwin15.6.0                  
     ui       RStudio                               
     language (EN)                                  
     collate  en_US.UTF-8                           
     ctype    en_US.UTF-8                           
     tz       America/New_York                      
     date     2019-02-13                            
    
    ─ Packages ──────────────────────────────────────────────────────────────────────────
     package     * version    date       lib source                        
     askpass       1.1        2019-01-13 [1] CRAN (R 3.5.2)                
     assertthat    0.2.0      2017-04-11 [1] CRAN (R 3.5.0)                
     backports     1.1.3      2018-12-14 [1] CRAN (R 3.5.0)                
     bindr         0.1.1      2018-03-13 [1] CRAN (R 3.5.0)                
     bindrcpp      0.2.2      2018-03-29 [1] CRAN (R 3.5.0)                
     broom         0.5.1      2018-12-05 [1] CRAN (R 3.5.1)                
     callr         3.1.1      2018-12-21 [1] CRAN (R 3.5.0)                
     cellranger    1.1.0      2016-07-27 [1] CRAN (R 3.5.0)                
     cli           1.0.1      2018-09-25 [1] CRAN (R 3.5.0)                
     colorspace    1.4-0      2019-01-13 [1] CRAN (R 3.5.2)                
     crayon        1.3.4      2017-09-16 [1] CRAN (R 3.5.0)                
     curl          3.3        2019-01-10 [1] CRAN (R 3.5.2)                
     desc          1.2.0      2018-05-01 [1] CRAN (R 3.5.0)                
     devtools    * 2.0.1      2018-10-26 [1] CRAN (R 3.5.1)                
     digest        0.6.18     2018-10-10 [1] CRAN (R 3.5.0)                
     dplyr       * 0.7.8      2018-11-10 [1] CRAN (R 3.5.0)                
     forcats     * 0.3.0      2018-02-19 [1] CRAN (R 3.5.0)                
     fs            1.2.6      2018-08-23 [1] CRAN (R 3.5.0)                
     generics      0.0.2      2018-11-29 [1] CRAN (R 3.5.0)                
     ggplot2     * 3.1.0      2018-10-25 [1] CRAN (R 3.5.0)                
     glue          1.3.0      2018-07-17 [1] CRAN (R 3.5.0)                
     gtable        0.2.0      2016-02-26 [1] CRAN (R 3.5.0)                
     haven         2.0.0      2018-11-22 [1] CRAN (R 3.5.0)                
     hms           0.4.2      2018-03-10 [1] CRAN (R 3.5.0)                
     httr          1.4.0      2018-12-11 [1] CRAN (R 3.5.0)                
     jsonlite      1.6        2018-12-07 [1] CRAN (R 3.5.0)                
     knitr         1.21       2018-12-10 [1] CRAN (R 3.5.2)                
     lattice       0.20-38    2018-11-04 [1] CRAN (R 3.5.2)                
     lazyeval      0.2.1      2017-10-29 [1] CRAN (R 3.5.0)                
     lubridate     1.7.4      2018-04-11 [1] CRAN (R 3.5.0)                
     magrittr      1.5        2014-11-22 [1] CRAN (R 3.5.0)                
     memoise       1.1.0      2017-04-21 [1] CRAN (R 3.5.0)                
     modelr        0.1.3      2019-02-05 [1] CRAN (R 3.5.2)                
     munsell       0.5.0      2018-06-12 [1] CRAN (R 3.5.0)                
     nlme          3.1-137    2018-04-07 [1] CRAN (R 3.5.2)                
     openssl       1.2.1      2019-01-17 [1] CRAN (R 3.5.2)                
     packrat       0.5.0      2018-11-14 [1] CRAN (R 3.5.0)                
     pillar        1.3.1      2018-12-15 [1] CRAN (R 3.5.0)                
     pkgbuild      1.0.2      2018-10-16 [1] CRAN (R 3.5.0)                
     pkgconfig     2.0.2      2018-08-16 [1] CRAN (R 3.5.0)                
     pkgload       1.0.2      2018-10-29 [1] CRAN (R 3.5.0)                
     plyr          1.8.4      2016-06-08 [1] CRAN (R 3.5.0)                
     prettyunits   1.0.2      2015-07-13 [1] CRAN (R 3.5.0)                
     processx      3.2.1      2018-12-05 [1] CRAN (R 3.5.0)                
     ps            1.3.0      2018-12-21 [1] CRAN (R 3.5.0)                
     purrr       * 0.3.0      2019-01-27 [1] CRAN (R 3.5.2)                
     R6            2.3.0      2018-10-04 [1] CRAN (R 3.5.0)                
     Rcpp        * 1.0.0      2018-11-07 [1] CRAN (R 3.5.0)                
     readr       * 1.3.1      2018-12-21 [1] CRAN (R 3.5.0)                
     readxl        1.2.0      2018-12-19 [1] CRAN (R 3.5.0)                
     remotes       2.0.2      2018-10-30 [1] CRAN (R 3.5.0)                
     rgeolocate  * 1.1.90000  2018-07-12 [1] local                         
     rlang         0.3.1      2019-01-08 [1] CRAN (R 3.5.2)                
     ropendata   * 0.1.0      2019-02-03 [1] local                         
     rprojroot     1.3-2      2018-01-03 [1] CRAN (R 3.5.0)                
     rstudioapi    0.9.0      2019-01-09 [1] CRAN (R 3.5.2)                
     rvest         0.3.2      2016-06-17 [1] CRAN (R 3.5.0)                
     scales        1.0.0.9000 2019-02-13 [1] Github (hadley/scales@c374014)
     sessioninfo   1.1.1      2018-11-05 [1] CRAN (R 3.5.0)                
     stringi     * 1.2.4      2018-07-20 [1] CRAN (R 3.5.0)                
     stringr     * 1.4.0      2019-02-10 [1] CRAN (R 3.5.2)                
     testthat      2.0.1      2018-10-13 [1] CRAN (R 3.5.0)                
     tibble      * 2.0.1      2019-01-12 [1] CRAN (R 3.5.2)                
     tidyr       * 0.8.2      2018-10-28 [1] CRAN (R 3.5.0)                
     tidyselect    0.2.5      2018-10-11 [1] CRAN (R 3.5.0)                
     tidyverse   * 1.2.1      2017-11-14 [1] CRAN (R 3.5.0)                
     udpprobe    * 0.2.1      2019-02-06 [1] local                         
     usethis     * 1.4.0      2018-08-14 [1] CRAN (R 3.5.0)                
     withr         2.1.2      2018-03-15 [1] CRAN (R 3.5.0)                
     xfun          0.4        2018-10-23 [1] CRAN (R 3.5.0)                
     xml2          1.2.0      2018-01-24 [1] CRAN (R 3.5.0)     
     