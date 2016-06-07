# National Exposure

![](national-exposure.svg)

Summary data & R Markdown files for <https://community.rapid7.com/community/infosec/blog/2016/06/07/rapid7-releases-new-research>

There are two other data files that may be of use to other researchers. The first is `counts_by_cc.rda` which is an R Data file containing summarized port counts by country and `study.ips` which is the cleaned, geolocated IP, country and port data set. There is an additional data set containing the raw `zmap` scan results which will be made available via <scans.io>.

You will need an Amazon AWS account to access these files (this GitHub repo does not have LFS enabled).

To see the files, issue the following:

    aws s3 ls s3://com.rapid7.external/national-exposure/

To copy the files, use the `sync` verb:

    aws s3 sync s3://com.rapid7.external/national-exposure/ .
   
NOTE that the Rmd file does not rely on these files. Rapid7 is providing them to bootstrap other researchers.
