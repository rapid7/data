# This provides a reproducible workflow for the rankings.
#
# The R data file has the ordered separate ranks as well as the weights 
#
# NOTE: This can take upwards of 30m to run on slower systems

library(RankAggreg)

load("rank.rdata")

out <- RankAggreg::RankAggreg(pre_rank, 50, seed=1492, importance=importance)
