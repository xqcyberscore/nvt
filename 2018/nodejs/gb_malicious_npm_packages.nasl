###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_malicious_npm_packages.nasl 10172 2018-06-13 07:41:24Z asteins $
#
# Malicious NPM package detection
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113208");
  script_version("$Revision: 10172 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-13 09:41:24 +0200 (Wed, 13 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-12 13:13:13 +0200 (Tue, 12 Jun 2018)");
  script_tag(name: "cvss_base", value: "7.5");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"Mitigation");

  script_cve_id("CVE-2017-16044", "CVE-2017-16045", "CVE-2017-16046", "CVE-2017-16047",
  "CVE-2017-16048", "CVE-2017-16049", "CVE-2017-16050", "CVE-2017-16051",
  "CVE-2017-16052", "CVE-2017-16053", "CVE-2017-16054", "CVE-2017-16055",
  "CVE-2017-16056", "CVE-2017-16057", "CVE-2017-16058", "CVE-2017-16059",
  "CVE-2017-16060", "CVE-2017-16061", "CVE-2017-16062", "CVE-2017-16063",
  "CVE-2017-16064", "CVE-2017-16065", "CVE-2017-16066", "CVE-2017-16067",
  "CVE-2017-16068", "CVE-2017-16069", "CVE-2017-16070", "CVE-2017-16071",
  "CVE-2017-16072", "CVE-2017-16073", "CVE-2017-16074", "CVE-2017-16075",
  "CVE-2017-16076", "CVE-2017-16077", "CVE-2017-16078", "CVE-2017-16079",
  "CVE-2017-16080", "CVE-2017-16081");

  script_name("Malicious NPM package detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/npms");

  script_tag(name:"summary", value:"Several NPM packages were of malicious nature. NPM has since removed them from their registry,
  but the packages could still be installed on a host.");
  script_tag(name:"vuldetect", value:"Checks if a malicious package is present on the target host.");
  script_tag(name:"impact", value:"The packages mostly extract information from environment variables,
  while some create a remote shell or a command-and-control infrastructure, completely comprising the target host.");
  script_tag(name:"affected", value:"Following packages are affected:

  - npm-script-demo

  - pandora-doomsday

  - botbait

  - d3.js

  - jquery.js

  - mariadb

  - mysqljs

  - node-sqlite

  - nodesqlite

  - sqlite.js

  - sqliter

  - node-fabric

  - fabric-js

  - nodefabric

  - sqlserver

  - mssql.js

  - nodemssql

  - gruntcli

  - mssql-node

  - babelcli

  - tkinter

  - node-tkinter

  - node-opensl

  - node-openssl

  - openssl.js

  - opencv.js

  - node-opencv

  - ffmepg

  - nodeffmpeg

  - nodecaffe

  - nodemailer-js

  - nodemailer.js

  - noderequest

  - crossenv

  - http-proxy.js

  - proxy.js

  - mongose

  - shadowsock

  - smb

  - nodesass

  - cross-env.js");

  script_tag(name:"solution", value:"- Delete the package

  - Clear your npm cache

  - Ensure it is not present in any other package.json files on your system

  - Regenerate your registry credentials, tokens, and any other sensitive credentials that may have been present in your environment variables.");

  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/480");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/481");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/482");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/483");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/484");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/485");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/486");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/487");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/488");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/489");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/490");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/491");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/492");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/493");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/494");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/495");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/496");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/497");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/498");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/499");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/500");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/501");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/502");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/503");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/504");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/505");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/506");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/507");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/508");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/509");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/510");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/511");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/512");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/513");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/514");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/515");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/516");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/517");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/518");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/519");
  script_xref(name:"URL", value:"https://nodesecurity.io/advisories/520");

  exit( 0 );
}

if( ! npms = get_kb_item( "ssh/login/npms" ) ) exit( 0 );

malicious_packages = make_list( 'd3.js', 'jquery.js', 'mariadb', 'mysqljs', 'node-sqlite',
                                'nodesqlite', 'sqlite.js', 'sqliter', 'node-fabric', 'fabric-js',
                                'nodefabric', 'sqlserver', 'mssql.js', 'nodemssql', 'gruntcli',
                                'mssql-node', 'babelcli', 'tkinter', 'node-tkinter', 'node-opensl',
                                'node-openssl', 'openssl.js', 'opencv.js', 'node-opencv', 'ffmpeg',
                                'nodeffmpeg', 'nodecaffe', 'nodemailer-js', 'nodemailer.js', 'noderequest',
                                'crossenv', 'http-proxy.js', 'proxy.js', 'mongose', 'shadowsock',
                                'smb', 'nodesass', 'cross-env.js', 'npm-script-demo', 'pandora-doomsday',
                                'botbait' );

vuln_text = NULL;

foreach pkg ( malicious_packages ) {
  matches = eregmatch( pattern: ' (' + pkg + ')@[0-9.]+', string: npms );
  if( ! isnull( matches[1] ) ) {
    if( isnull( vuln_text ) ) {
      vuln_text = '  - ' + pkg;
    }
    else {
      vuln_text += '\r\n  - ' + pkg;
    }
  }
}

if( vuln_text ) {
  report = 'The following malicious packages were found on the target host:\r\n\r\n' + vuln_text;
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
