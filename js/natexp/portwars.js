var primary_col = "#045bab";
var secondary_col = "#b7404c";
var easy = "quad";
var wait = 100;
var long = 500;
var sw = 0.75;
var so = 1;
var yofs = 5;
var ann_size = 9;
var y_max = 184;

var tf ;

var cat_map = { "web"   : { t:"HTTPS",             b:"HTTP"   }, 
                "shell" : { t:"ssh",               b:"Telnet" },
                "smtp"  : { t:"SMTPS",             b:"SMTP"   }, 
                "pop"   : { t:"POP3 over TLS SSL", b:"POP3"   }, 
                "imap"  : { t:"IMAP over SSL",     b:"IMAP"   } };


var percent = d3.format(",%");

var tip = d3.tip()
            .attr('class', 'd3-tip')
            .offset([-10, 0])
            .html(function(d) { return("<b>" + d.country + "</b>") });

var margin_main = { top: 1, right: 30, bottom: 1, left: 30 };
var main_width = 800 - margin_main.left - margin_main.right;
var main_height = 240 - margin_main.top - margin_main.bottom;

var x = d3.scale.linear()
          .domain([0, y_max])
          .range([0, main_width]);

var y = d3.scale.linear()
          .domain([-1, 1])
          .range([main_height, 0]);

var main_svg = d3.select("#natexp_main")
                 .append("svg")
                 .attr("width", main_width + margin_main.left + margin_main.right)
                 .attr("height", main_height + margin_main.top + margin_main.bottom)
                 .append("g")
                 .attr("transform", "translate(" + margin_main.left + "," + margin_main.top + ")");

var tab = d3.select("#tb");

// setup background y axis grid

main_svg.selectAll('.grid')
        .data([ {y:-0.5, s:0.5}, {y:0.5, s:0.5}, {y:0, s:1}, {y:1, s:0.25}, {y:-1, s:0.25} ])
        .enter()
        .append("line")
        .classed("grid", true)
        .attr("stroke-width", function(d) { return(d.s) })
        .attr("stroke", "#2b2b2b")
        .attr("stroke-opacity", 0.5)
        .attr("shape-rendering", "crisp-edges")
        .attr("x1", x(0))
        .attr("x2", x(y_max))
        .attr("y1", function(d) { return(y(d.y)) })
        .attr("y2", function(d) { return(y(d.y)) });

// setup left/right axis labels

main_svg.selectAll(".yaxis")
        .data([ 1, 0.5, 0.1, -0.1, -0.5, -1 ])
        .enter()
        .append("text")
        .style("font-size", ann_size)
        .style("alignment-baseline", function(d) { 
          if (d==1) return("hanging");
          if (d==-1) return("auto");
          return("middle"); 
        })
        .style("text-anchor", function(d) { return(d<=0 ? "end": "start") })
        .attr("x", function(d) { return(d<=0 ? -5 : x(y_max)+5) })
        .attr("y", function(d) { return(y( Math.abs(d)==0.1 ? 0 : d )) })
        .text(function(d) { return(percent( Math.abs(d)==0.1 ? 0 : Math.abs(d) )) })

// setup top/bottom protocol labels

main_svg.selectAll(".xtl")
        .data([cat_map["web"].t])
        .enter()
        .append("text")
        .classed("xtl", true)
        .attr("x", 0)
        .attr("y", y(1)+yofs)
        .style("font-size", ann_size)
        .style("text-anchor", "start")
        .style("alignment-baseline", "hanging")
        .text(function(d) { return(d) });

main_svg.selectAll(".xtr")
        .data([cat_map["web"].b])
        .enter()
        .append("text")
        .classed("xtr", true)
        .attr("x", x(y_max))
        .attr("y", y(-1)-yofs)
        .style("font-size", ann_size)
        .style("text-anchor", "end")
        .style("alignment-baseline", "auto")
        .text(function(d) { return(d) });

// actually draw the segments

function is_cat(category) { return(function(d) { return(d.category === category) }) }

function update_segments(cat) {

  main_svg.selectAll(".xtl").data([cat_map[cat].t]).text(function(d) { return(d) });
  main_svg.selectAll(".xtr").data([cat_map[cat].b]).text(function(d) { return(d) });

  var sub = dat.filter(is_cat(cat));

  var segs = main_svg.selectAll('.segment').data(sub);

  segs.enter()
      .append("line")
      .classed("segment", true)
      .attr("stroke-width", sw)
      .attr("stroke-opacity", so)
      .attr("shape-rendering", "crisp-edges")
      .attr("stroke", function(d) { return(d.encrypted ? primary_col : secondary_col) })
      .on('mouseover', function(d) { tip.show(d) })
      .on('mouseout',  function(d) { tip.hide(d) });

  segs.transition()
      .ease(easy)
      .delay(wait)
      .duration(long)
      .attr("x1", function(d) { return(x(d.x))   })
      .attr("x2", function(d) { return(x(d.x))   })
      .attr("y1", function(d) { return(y(0))     })
      .attr("y2", function(d) { return(y(d.pct)) });

  segs.exit().remove();

  segs.call(tip);

  var tab_dat = d3.nest()
                  .key(ƒ('country'))
                  .key(ƒ('encrypted'))
                  .entries(sub);

  tab.selectAll("tr").remove();

  var trs = tab.selectAll("tr")
     .data(tab_dat)
     .enter()
     .append("tr");
  
  var tds = trs.selectAll("td")
               .data(function(row, i) {
                 return([ { c: row.key                         },
                          { c: row.values[0].values[0].tot_lab },
                          { c: row.values[0].values[0].n_lab   },
                          { c: row.values[0].values[0].pct_lab },
                          { c: row.values[1] === undefined ? "0" : row.values[1].values[0].n_lab   },
                          { c: row.values[1] === undefined ? "0%" : row.values[1].values[0].pct_lab   },
                        ])
               })
               .enter()
               .append("td")
               .html(ƒ('c'));

  tds.html(ƒ('c'));

  tf.init();
}

tf = new TableFilter("tab", {
  base_path: "/js/tablefilter/",
  auto_filter: true,
  auto_filter_delay: 800, //milliseconds
  filters_row_index: 1,
  state: {
    types: ['local_storage'],
    filters: true,
  },
  btn_reset: true,
});

update_segments("web");

tf.init();

d3.select('#pairs')
  .on("change", function() { update_segments(d3.select(this).property("value")) });
