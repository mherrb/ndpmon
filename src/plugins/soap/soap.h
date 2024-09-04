#ifndef _SOAP_H_
#define _SOAP_H_

#include <openssl/x509.h>
#include <openssl/objects.h>
#include <libcsoap/soap-client.h>
#include <libcsoap/soap-server.h>
#include <libcsoap/soap-ctx.h>
#include <nanohttp/nanohttp-common.h>
#define HAVE_SSL 1
#include <nanohttp/nanohttp-ssl.h>

#include "../../core/alerts.h"
#include "../../core/neighbors.h"
#include "../../core/parser.h"
#include "../../core/probes.h"
#include "../../core/events.h"
#include "../../core/extinfo.h"
#include "../../core/settings.h"

/** @file
 *  SOAP plugin.
 */

/** Maximum length of URL and path identifiers in the SOAP plugin. */
#define SOAP_STR_SIZE 256
/** Uniform ressource name for NDPMon SOAP content. */
#define SOAP_URN_STR "urn:ndpmon_soap_message"

/** Settings for the soap plugin. */
struct soap_settings {
    /** Push events to a soap router (1=yes, 0=disabled)? */
    int soap_report_enabled;
    /** Server name to report events to. */
    char soap_report_url[SOAP_STR_SIZE];
    /** Source to include in reports. */
    char soap_report_src[SOAP_STR_SIZE];
    /** Listen for reports (1=yes, 0=disabled)? */
    int soap_listen_enabled;
    /** Path under which the SOAP router will run. */
    char soap_listen_path[SOAP_STR_SIZE];
    /** Port under which the SOAP server will run. */
    unsigned int soap_listen_port;
    /** Whether to use secured transport (1=yes, 0=disabled). */
    int ssl_enabled;
    /** SSL Certificate Chain File */
    char ssl_certfile[SOAP_STR_SIZE];
    /** SSL Certificate Encryption Password */
    char ssl_certpass[SOAP_STR_SIZE];
    /** SSL CA File */
    char ssl_cafile[SOAP_STR_SIZE];
    /** Common Name of the certificate issuer */
    char ssl_commonname[SOAP_STR_SIZE];
};

/** Tears down the SOAP plugin.
 */
void soap_down();

/** Handler to send all events that occur to a configure server.
 *  @param event Event to be reported.
 */
void soap_event_handler(const struct event_info* event);

/** Creates a soap method context with a XML body for a given method.
 *  @param request The request to be created (call by reference).
 *  @param method  The method name.
 *  @param source  This NDPMon instance source identifier.
 *  @return        The method context XML body on success or NULL on error.
 */
xmlNodePtr soap_method_create(SoapCtx** request, const char* method, const char* source);

/** Sends a given soap context to the report server.
 *  @param request The request to be sent.
 *  @param url     URL at which the service router can be found.
 *  @return        0 on success, -1 on error.
 */
int soap_method_send(SoapCtx* request, const char* url);

/** The SOAP server thread.
 *  @param args Unused.
 */
void* soap_listen(void* args);

/** Service method for the alert event.
 *  @param request The SOAP request.
 *  @param result  Will hold the SOAP response.
 *  @return        H_OK on success or a herror_t otherwise.
 */
herror_t soap_listen_alert(SoapCtx *request, SoapCtx *result);

/** Service method for the neighbor update event.
 *  @param request The SOAP request.
 *  @param result  Will hold the SOAP response.
 *  @return        H_OK on success or a herror_t otherwise.
 */
herror_t soap_listen_neighbor_update(SoapCtx *request, SoapCtx *result);

/** Service method for the probe_updown event.
 *  @param request The SOAP request.
 *  @param result  Will hold the SOAP response.
 *  @return        H_OK on success or a herror_t otherwise.
 */
herror_t soap_listen_probe_updown(SoapCtx *request, SoapCtx *result);

/** Frees allocated soap settings.
 *  @param data The soap settings structure (call by reference).
 */
void soap_settings_free(void** data);

/** Loads soap settings from an XML element.
 *  @param element Element to load the information from.
 *  @param data    soap_settings structure to hold the information
 *                 (call by reference).
 *  @return        0 on success, -1 on error.
 */
int soap_settings_load(xmlNodePtr element, void** data);

/** Prints the given soap settings.
 *  @param data soap_settings structure to be printed.
 */
void soap_settings_print(void* data);

/** Saves soap settings to an XML element.
 *  @param element Element to add the information to.
 *  @param data    Settings to be saved.
 *  @return        Always 0 (success).
 */
int soap_settings_save(xmlNodePtr element, void* data);

/** Initializes the SOAP plugin.
 */
void soap_up();

#if 0
/* Verify the given certificate.
 * @param cert The certificate.
 * @return     1 if OK, 0 if required value does not match.
 */
int soap_ssl_verify(X509* cert);
#endif


#endif
