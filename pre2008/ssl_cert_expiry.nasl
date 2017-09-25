###############################################################################
# OpenVAS Vulnerability Test
# $Id: ssl_cert_expiry.nasl 7242 2017-09-23 14:58:39Z cfischer $
#
# SSL/TLS: Certificate Expiry
#
# Authors:
# George A. Theall, <theall@tifaware.com>
# Werner Koch <wk@gnupg.org>
#
# Copyright:
# Copyright (C) 2004 George A. Theall
# Copyright (C) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# How far (in days) to warn of certificate expiry. [Hmmm, how often
# will scans be run and how quickly can people obtain new certs???]
lookahead = 60;

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15901");
  script_version("$Revision: 7242 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-23 16:58:39 +0200 (Sat, 23 Sep 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SSL/TLS: Certificate Expiry");

  # (deprecated: once openvas-libaries < 6.0 are not supported anymore
  # this script can be removed in favor of gb_ssl_cert_expired.nasl)

  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_dependencies("secpod_ssl_ciphers.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_tag(name:"solution", value:"Purchase or generate a new SSL/TLS certificate to replace the existing
  one.");
  script_tag(name:"summary", value:"The remote server's SSL/TLS certificate has already expired or will expire
  shortly.

  Description :

  This script checks expiry dates of certificates associated with
  SSL/TLS-enabled services on the target and reports whether any have
  already expired or will expire shortly.

  This NVT has been replaced by NVT 'SSL/TLS: Certificate Expired' (OID: 1.3.6.1.4.1.25623.1.0.103955).");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

if(int(OPENVAS_VERSION[0]) >= 7)exit(0); # with libraries >= 7 the more recent gb_ssl_cert_expired.nasl take this job.

include("global_settings.inc");
include("misc_func.inc");
include("ssl_funcs.inc");
include("byte_func.inc");

# This function converts a date expressed as:
#   Year(2)|Month(2)|Day(2)|Hour(2)|Min(2)|Sec(2)
# and returns it in a more human-friendly format.
function x509time_to_gtime(x509time) {
  local_var parts, gtime;

  if (x509time && x509time =~ "^[0-9]{12}Z?$") {
    for (i=0; i<= 6; ++i) {
      parts[i] = substr(x509time, i*2, i*2+1);
    }

    if (parts[0] =~ "^9") year = string("19", parts[0]);
    else year = string("20", parts[0]);

    mm = int(parts[1]);
    if(mm<10) mm = '0' + mm;

    gtime = year + '-' + mm + '-' + parts[2] + ' ' +  parts[3] + ':' +  parts[4] + ':' + parts[5] + ' GMT';

  }
  return gtime;
}

port = get_ssl_port();
if( ! port ) exit( 0 );

cert = get_server_cert(port:port, encoding:"der");

if (defined_func("cert_open") && ! isnull( cert )) {
  # We have the new certificate API.  Thus e can use this more
  # robust code.
  local_var certobj, valid_start, valid_end;

  certobj = cert_open(cert);
  if (!certobj) {
    log_message(data:string("The SSL certificate of the remote service ",
                                 "can't be parsed!"),
                     port:port);
    exit(0);
  }

  valid_start = cert_query(certobj, "not-before");
  valid_end   = cert_query(certobj, "not-after");

  if (log_verbosity > 1)
    debug_print("The SSL certificate on port ", port,
                " is valid between ", valid_start, " and ",
                valid_end, ".", level:0);

  now = isotime_now();
  if( strlen( now ) <= 0 ) exit( 0 ); # isotime_now: "If the current time is not available an empty string is returned."
  future = isotime_add(now, days:lookahead);
  if( isnull( future ) ) exit( 0 ); # isotime_add: "or NULL if the provided ISO time string is not valid or the result would overflow (i.e. year > 9999).

  if (valid_start > now) {
    log_message(data:string("The SSL certificate of the remote service ",
                              "is not valid before ",
                              isotime_print(valid_start), " UTC!"),
                  port:port);
  }
  else if (valid_end < now) {
    log_message(data:string("The SSL certificate of the remote service ",
                                 "expired on ",
                                 isotime_print(valid_end), " UTC!"),
                     port:port);
  }
  else if (valid_end < future) {
    log_message(data:string("The SSL certificate of the remote service ",
                              "will expire within ", lookahead, " days, at ",
                              isotime_print(valid_end), " UTC."),
                  port:port);
  } else {
    future = isotime_add(now, years:15);
    if( isnull( future ) ) exit( 0 ); # isotime_add: "or NULL if the provided ISO time string is not valid or the result would overflow (i.e. year > 9999).
    if (valid_end > future) {
        log_message(data:string("The SSL certificate of the remote service ",
                                  "is valid for more than 15 years from now ",
                                  "(until ", isotime_print(valid_end), ")."),
                      port:port);
    }
    log_message(data:string("The SSL certificate of the remote service ",
                            "is valid between ",
                            isotime_print(valid_start), " and ",
                            isotime_print(valid_end), " UTC."),
                port:port);
  }

  cert_close(certobj);
}
else if (!isnull(cert)) {
  # Use The old and fragile code.  It has some flaws, for example it
  # does not report a missing certificate or certificates which are
  # valid but encoded in a slightly different way.
  #
  # nb: maybe someday I'll actually *parse* ASN.1.
  v = stridx(cert, raw_string(0x30, 0x1e, 0x17, 0x0d));
  if (v >= 0) {
    v += 4;
    valid_start = substr(cert, v, v+11);
    v += 15;
    valid_end = substr(cert, v, v+11);

    if (valid_start =~ "^[0-9]{12}$" && valid_end =~ "^[0-9]{12}$") {
      # Get dates, expressed in UTC, for checking certs.
      # - right now.
      tm = localtime(unixtime(), utc:TRUE);
      now = substr(string(tm["year"]), 2);
      foreach field (make_list("mon", "mday", "hour", "min", "sec")) {
        if (tm[field] < 10) now += "0";
        now += tm[field];
      }
      # - 'lookahead' days in the future.
      tm = localtime(unixtime() + lookahead*24*60*60, utc:TRUE);
      future = substr(string(tm["year"]), 2);
      foreach field (make_list("mon", "mday", "hour", "min", "sec")) {
        if (tm[field] < 10) future += "0";
        future += tm[field];
      }
      debug_print("now:    ", now, ".");
      debug_print("future: ", future, ".");

      valid_start_alt = x509time_to_gtime(x509time:valid_start);
      valid_end_alt = x509time_to_gtime(x509time:valid_end);
      debug_print("valid not before: ", valid_start_alt, " (", valid_start, "Z).");
      debug_print("valid not after:  ", valid_end_alt,   " (", valid_end, "Z).");

      if (log_verbosity > 1)
        debug_print("The SSL certificate on port ", port,
                    " is valid between ", valid_start_alt, " and ",
                    valid_end_alt, ".", level:0);

      if (valid_start > now) {
        log_message(
          data:string("The SSL certificate of the remote service is not valid before ", valid_start_alt, "!"),
          port:port
        );
      }
      else if (valid_end < now) {
        log_message(
          data:string("The SSL certificate of the remote service expired ", valid_end_alt, "!"),
          port:port
        );
      }
      else if (valid_end < future) {
        log_message(
          data:string("The SSL certificate of the remote service will expire within\n", lookahead, " days, at ", valid_end_alt, "."),
          port:port
        );
      } else {
         log_message(port:port,data:string("The SSL certificate of the remote service is valid between\n", valid_start_alt, " and ", valid_end_alt, "."));
      }
    }
  }
}
