/**
 * Namf_EventExposure
 * AMF Event Exposure Service © 2019, 3GPP Organizational Partners (ARIB, ATIS,
 * CCSA, ETSI, TSDSI, TTA, TTC). All rights reserved.
 *
 * The version of the OpenAPI document: 1.1.0.alpha-1
 *
 *
 * NOTE: This class is auto generated by OpenAPI Generator
 * (https://openapi-generator.tech). https://openapi-generator.tech Do not edit
 * the class manually.
 */

/*
 * IndividualSubscriptionDocumentApiImplEventExposure.h
 *
 *
 */

#ifndef INDIVIDUAL_SUBSCRIPTION_DOCUMENT_API_IMPL_EVENT_EXPOSURE_H_
#define INDIVIDUAL_SUBSCRIPTION_DOCUMENT_API_IMPL_EVENT_EXPOSURE_H_

#include <pistache/endpoint.h>
#include <pistache/http.h>
#include <pistache/router.h>
#include <memory>

#include <IndividualSubscriptionDocumentApiEventExposure.h>

#include <pistache/optional.h>

#include "AmfUpdatedEventSubscription.h"
//#include "OneOfarrayAmfUpdateEventOptionItem.h"
#include "ProblemDetails.h"
#include "AmfUpdateEventOptionItem.h"
#include <string>

#include "amf_app.hpp"

namespace oai {
namespace amf {
namespace api {

using namespace oai::model::amf;
using namespace oai::amf::api;

class IndividualSubscriptionDocumentApiImplEventExposure
    : public IndividualSubscriptionDocumentApiEventExposure {
 public:
  explicit IndividualSubscriptionDocumentApiImplEventExposure(
      const std::shared_ptr<Pistache::Rest::Router>&,
      amf_application::amf_app* amf_app_inst);
  ~IndividualSubscriptionDocumentApiImplEventExposure() override = default;

  void delete_subscription(
      const std::string& subscriptionId,
      Pistache::Http::ResponseWriter& response);
  void modify_subscription(
      const std::string& subscriptionId,
      const AmfUpdateEventOptionItem& amfUpdateEventOptionItem,
      Pistache::Http::ResponseWriter& response);

 private:
  amf_application::amf_app* m_amf_app;
};

}  // namespace api
}  // namespace amf
}  // namespace oai

#endif