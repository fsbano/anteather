var vulnerability

class Anteather {

  constructor(name) {
    this.SCANNER = name
  }

  get trivy() {

    var CRITICAL = 0
    var IMPORTANT = 0
    var MODERATE = 0
    var LOW = 0  
    
    console.log ("Trivy - Vulnerability Static Analysis for Containers")
    var TRIVY = $.getJSON( "trivy.json", function() {
      $.each(TRIVY, function(key, value) {
        $.each(value.Results, function(k, v) {
          $.each(v.Vulnerabilities, function(l, j) {
            if (j.Severity == "CRITICAL") { CRITICAL++ }
            if (j.Severity == "HIGH") { IMPORTANT++ }
            if (j.Severity == "MEDIUM") { MODERATE++ }
            if (j.Severity == "LOW") { LOW++ }
          });
        });
      });

      const ctx = document.getElementById('doughnutChart').getContext('2d');
      if ( typeof vulnerability === 'object' ) { vulnerability.destroy(); }
      vulnerability = new Chart(ctx, {
        plugins: [ChartDataLabels],
        type: 'doughnut',
        data: {
            labels: ['Critical', 'Important', 'Moderate', 'Low'],
            datasets: [{
                data: [CRITICAL, IMPORTANT, MODERATE, LOW],
                backgroundColor: [
                    'rgba(255, 99, 132)',
                    'rgba(54, 162, 235)',
                    'rgba(255, 206, 86)',
                    'rgba(75, 192, 192)',
                ],
            }]
        },
        options: {
          cutout: "70%",
            plugins: {
              legend: {
                display: true,
              },
              title: {
                display: true,
                text: 'Trivy - Container Security Scanner'
              },
              subtitle: {
                display: true,
                text: 'registry.access.redhat.com/ubi7/ubi:7.6-73'
              }
            }
        }
      });
    });

    var vulnerabilityDetail = $.getJSON( "trivy.json", function() {
    var text = "<table border='0' align='center' width='100%'>";
    text += "<th>Package</th><th>Distribuition</th><th>Version</th><th>CVE</th>";
    $.each(vulnerabilityDetail, function(key, value) {
      $.each(value.Results, function(k, v) {
        $.each(v.Vulnerabilities, function(w, z) {
          text += "<tr>";
          text += "<td>" + z.PkgName + "</td><td align='center'>" + v.Type + "</td><td align='center'> 7 </td><td align='center'>" + z.VulnerabilityID + "</td>";
          text += "</tr>";
        });
      });
    });
    text += "</table>";
    document.getElementById("tableData").innerHTML = text;
    });  

  }


  get grype() {

    var CRITICAL = 0
    var IMPORTANT = 0
    var MODERATE = 0
    var LOW = 0  
    
    console.log ("Grype - Vulnerability Static Analysis for Containers")
    var GRYPE = $.getJSON( "grype.json", function() {
      $.each(GRYPE, function(key, value) {
        $.each(value.matches, function(k, v) {
          if (v.vulnerability.severity == "Critical") { CRITICAL++ }
          if (v.vulnerability.severity == "High") { IMPORTANT++ }
          if (v.vulnerability.severity == "Medium") { MODERATE++ }
          if (v.vulnerability.severity == "Low") { LOW++ }
        });
      });

      const ctx = document.getElementById('doughnutChart').getContext('2d');
      if ( typeof vulnerability === 'object' ) { vulnerability.destroy(); }
      vulnerability = new Chart(ctx, {
        plugins: [ChartDataLabels],
        type: 'doughnut',
        data: {
            labels: ['Critical', 'Important', 'Moderate', 'Low'],
            datasets: [{
                data: [CRITICAL, IMPORTANT, MODERATE, LOW],
                backgroundColor: [
                    'rgba(255, 99, 132)',
                    'rgba(54, 162, 235)',
                    'rgba(255, 206, 86)',
                    'rgba(75, 192, 192)',
                ],
            }]
        },
        options: {
          cutout: "70%",
            plugins: {
              legend: {
                display: true,
              },
              title: {
                display: true,
                text: 'Grype - Container Security Scanner'
              },
              subtitle: {
                display: true,
                text: 'registry.access.redhat.com/ubi7/ubi:7.6-73'
              }
            }
        }
      });
    });

    var vulnerabilityDetail = $.getJSON( "grype.json", function() {
    var text = "<table border='0' align='center' width='100%'>";
    text += "<th>Package</th><th>Distribuition</th><th>Version</th><th>CVE</th>";
    $.each(vulnerabilityDetail, function(key, value) {
      $.each(value.matches, function(k, v) {
        $.each(v.matchDetails, function(w, z) {
          text += "<tr>";
          text += "<td>" + z.searchedBy.package.name + "</td><td align='center'>" + z.searchedBy.distro.type + "</td><td align='center'>" + z.searchedBy.distro.version + "</td><td align='center'>" + v.vulnerability.id + "</td>";
          text += "</tr>";
        });
      });
    });
    text += "</table>";
    document.getElementById("tableData").innerHTML = text;
    });  

  }

  get clair() {

    var CRITICAL = 0
    var IMPORTANT = 0
    var MODERATE = 0
    var LOW = 0  
    
    console.log ("Clair - Vulnerability Static Analysis for Containers")
    var CLAIR = $.getJSON( "clair.json", function() {
      $.each(CLAIR, function(key, value) {
        $.each(value.vulnerabilities, function(k, v) {
          if (v.severity == "Critical") { CRITICAL++ }
          if (v.severity == "Important") { IMPORTANT++ }
          if (v.severity == "Moderate") { MODERATE++ }
          if (v.severity == "Low") { LOW++ }
        });
      });

      const ctx = document.getElementById('doughnutChart').getContext('2d');
      if ( typeof vulnerability === 'object' ) { vulnerability.destroy(); }
      vulnerability = new Chart(ctx, {
        plugins: [ChartDataLabels],
        type: 'doughnut',
        data: {
            labels: ['Critical', 'Important', 'Moderate', 'Low'],
            datasets: [{
                data: [CRITICAL, IMPORTANT, MODERATE, LOW],
                backgroundColor: [
                    'rgba(255, 99, 132)',
                    'rgba(54, 162, 235)',
                    'rgba(255, 206, 86)',
                    'rgba(75, 192, 192)',
                ],
            }]
        },
        options: {
          cutout: "70%",
            plugins: {
              legend: {
                display: true,
              },
              title: {
                display: true,
                text: 'Clair - Container Security Scanner'
              },
              subtitle: {
                display: true,
                text: 'registry.access.redhat.com/ubi7/ubi:7.6-73'
              }
            }
        }
      });
   });

    var vulnerabilityDetail = $.getJSON( "clair.json", function() {
    var text = "<table border='0' align='center' width='100%'>";
    text += "<th>Package</th><th>Distribuition</th><th>Version</th><th>CVE</th>";
    $.each(vulnerabilityDetail, function(key, value) {
      $.each(value.vulnerabilities, function(k, v) {
        text += "<tr>";
        text += "<td>" + v.package.name + "</td><td>" + v.distribution.name + "</td><td align='center'>" + v.distribution.version_id + "</td><td>" + v.name + "</td>";
        text += "</tr>";
      });
    });
    text += "</table>";
    document.getElementById("tableData").innerHTML = text;
    });

  }

  get doughnutChart() {
    if (this.SCANNER == "clair") { this.clair }
    if (this.SCANNER == "grype") { this.grype }
    if (this.SCANNER == "trivy") { this.trivy }
  }

}

var scanner = function(value) {
  var anteather = new Anteather(value);
  anteather.doughnutChart;
}
