
var comma_format = d3.format("0,000");

var tip = d3.tip()
            .attr('class', 'd3-tip')
            .offset([-10, 0])
            .html(function(d) {
              return "<strong>Country:</strong> " + d.country + "<br/>" + 
                     "<strong>% of devices with " + d.y + (d.y>1 ? " ports" : " port ") + " open:</strong> " + d.percent + "<br/>" +
                     "<strong># devices with " + d.y + (d.y>1 ? " ports" : " port ") + " open:</strong> " + comma_format(d.ct) + "<br/>" +
                     "<strong>Total devices:</strong> " + comma_format(d.total); });

var show_min = 1;
var showing = dat.filter(function(d) { return(d.x >= 1 & d.x <= 50) })

var count_fill = false;

var dat_color = d3.scale
                  .linear()
                  .domain([0,0.125,0.25,0.375,0.5,0.625,0.75,0.875,1])
                  .range(['#b2182b','#d6604d','#f4a582','#fddbc7','#f7f7f7','#d1e5f0','#92c5de','#4393c3','#2166ac'].reverse());
// virids didn't have enough contrast on a white background
//                  .range(["#440154","#472D7B","#3B528B","#2C728E","#21908C","#27AD81","#5DC863","#AADC32","#FDE725"]);

var dat_color_count = d3.scale
                        .linear()
                        .domain([0,2.0739,4.1477,6.2216,8.2954,10.3693,12.4432,14.517,16.5909] )
                        .range(['#b2182b','#d6604d','#f4a582','#fddbc7','#f7f7f7','#d1e5f0','#92c5de','#4393c3','#2166ac'].reverse());
// virids didn't have enough contrast on a white background
//                        .range(["#440154","#472D7B","#3B528B","#2C728E","#21908C","#27AD81","#5DC863","#AADC32","#FDE725"]);

var margin_show = {top: 1, right: 1, bottom: 1, left: 90};
var margin_pan =  {top: 1, right: 1, bottom: 1, left: 90};

var show_width = 960 - margin_show.left - margin_show.right;
var show_height = 400 - margin_show.top - margin_show.bottom;

var pan_width = 960 - margin_pan.left - margin_pan.right;
var pan_height = 20 - margin_pan.top - margin_pan.bottom;

var gridSizeW = show_width / 50;
var gridSizeH = show_height / 30;

var x = d3.scale.linear()
          .domain([1, 185])
          .range([0, pan_width]);

var y = d3.scale.linear()
          .domain([1, 30])
          .range([30, 1]);

var main_svg = d3.select("#main")
                 .append("svg")
                 .attr("width", show_width + margin_show.left + margin_show.right)
                 .attr("height", show_height + margin_show.top + margin_show.bottom)
                 .append("g")
                 .attr("transform", "translate(" + margin_show.left + "," + margin_show.top + ")");

var rows = main_svg.selectAll(".ylab") 
                   .data(["(# ports open) 30", "29", "28", "27","26","25","24","23","22","21","20","19","18","17","16",
                          "15","14","13","12","11","10","9","8","7","6","5","4","3","2","1"] )
                   .enter()
                   .append("text")
                   .classed("ylab", true)
                   .attr("x", -4)
                   .attr("y", function(d, i) { return(i * gridSizeH + (gridSizeH/1.1)); })
                   .text(function(d) { return(d); })

var xtnts = { "x" : 1, "y" : 1 };

var bins = main_svg.selectAll(".bin")
             .data(showing, function(d, i) { return(i); })
             .enter()
             .append("rect")
             .classed("bin", true)
             .attr("x", function(d) { return (d.x - xtnts.x) * gridSizeW;    })
             .attr("y", function(d) { return (y(d.y) - xtnts.y) * gridSizeH; })
             .attr("width", gridSizeW)
             .attr("height", gridSizeH)
             .attr("stroke", "white")
             .attr("stroke-width", "0.5px")
             .attr("stroke-opacity", 0.8)
             .attr("fill", function(d) { 
                if (d.ct == -1) return("#bdbdbd");
                if (count_fill) {
                  return(dat_color_count(d.ct));
                } else {
                  return(dat_color(d.pct));
                }
              })
             .on('mouseover', function(d) {
                if (d.ct == -1) return;
                this.parentNode.appendChild(this);
                d3.select(this).attr("stroke-width", "4px").attr("stroke-opacity", 1);
                tip.show(d);
              })
             .on('mouseout', function(d) { 
                d3.select(this).attr("stroke-width", "0.5px").attr("stroke-opacity", 0.8);
                tip.hide(d);
              });

bins.call(tip);

var brush = d3.svg
              .brush()
              .x(x)
              .extent([1, 50])
              .on("brush", brushed);

var svg = d3.select("#pan")
            .append("svg")
            .attr("width", pan_width + margin_pan.left + margin_pan.right)
            .attr("height", pan_height + margin_pan.top + margin_pan.bottom)
            .append("g")
            .attr("transform", "translate(" + margin_pan.left + "," + margin_pan.top + ")");

svg.append("rect")
    .attr("class", "grid-background")
    .attr("width", pan_width)
    .attr("height", pan_height);

svg.append("g")
    .attr("class", "x grid")
    .attr("transform", "translate(0," + pan_height + ")")
    .call(d3.svg.axis()
                .scale(x)
                .orient("bottom")
                .ticks(185)
                .tickSize(-pan_height)
                .tickFormat(""));

var gBrush = svg.append("g")
    .attr("class", "brush")
    .call(brush);

gBrush.selectAll("rect").attr("height", pan_height);

function update(data, transition) {

   var bins = main_svg.selectAll(".bin").data(data, function(d, i) { return(i); });

   bins.attr("x", function(d) { return (d.x - xtnts.x) * gridSizeW;    })
       .attr("y", function(d) { return (y(d.y) - xtnts.y) * gridSizeH; })

   // the way higlighted cells are brought to the front "messes" with the d3 svg inner element ordering
   // and creates an undesirable transition effect, so we first reorder the visualization to its original
   // state then switch them with transition so it looks smoother.

   bins.attr("fill", function(d) { 
     if (d.ct == -1) return("#bdbdbd");
     if (count_fill) {
       return(dat_color(d.pct));
     } else {
       return(dat_color_count(Math.log(d.ct)));
     }
    });

   if (transition) bins = bins.transition(250);

   bins.attr("fill", function(d) { 
     if (d.ct == -1) return("#bdbdbd");
     if (count_fill) {
       return(dat_color_count(Math.log(d.ct)));
     } else {
       return(dat_color(d.pct));
     }
    });

}

function brushed() {

  var extent = brush.extent();

  extent[0] = d3.round(extent[0]);
  extent[1] = d3.round(extent[1]);

  console.log("brushed " + extent[0] + " " + extent[1]);
 
  // we don't want the 50px brush to go "off screen" so we ensure it's clipped

  if ((extent[1] - extent[0] + 1) != 50) { extent[1] = extent[0] + 50 ; }
  if (extent[0] > 135) {
    extent[0] = 135;
    extent[1] = extent[0] + 50 ;
  }

  d3.select(this).call(brush.extent(extent));

  showing = dat.filter(function(d) { return(d.x >= extent[0] & d.x <= extent[1]) })

  xtnts.x = extent[0] ;
  xtnts.y = 1 ;

  update(showing) ;
   
}

toggle_fill = function(x) {
  count_fill = x.checked;
  update(showing, true) ;
}
