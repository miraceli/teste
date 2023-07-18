import io

import dateutil.parser
from django.db.models import Prefetch, Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import generics, permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.filters import OrderingFilter
from rest_framework.response import Response
from rest_framework.views import APIView


from appActivity.models import PatientActivity
from appActivity.serializers import PatientActivitySerializer
from appBase.mixins import ExportMixin
from appBase.pagination import BasePagination
from appBase.utils import get_client_ip
from appCalendar.models import Meeting
from appDataSet.models.city_state import State
from appDataSet.serializers.professions_serializer import ProfessionsSerializer
from appDocs.models.documents.exam import ExamOrder
from appDocs.models.documents.medical_certificate import (
    MedicalCertificate, OccupationalHealthCertificate)
from appDocs.models.documents.prescription import Prescription
from appPatientUpdate.views import HistoricFromObjectMixin
from appSectorRisks.models import HarmfulAgent
from appStorage.models import File
from appUser.models import ActiveRole
from appUser.permissions import APIUserPermissions
from appUser.utils import get_user_role_instance

from . import filters
from . import permissions as custom_permissions
from . import serializers
from .filters import CareteamFilter
from .mixins import AddProfessionalToCompanyGroup
from .models import (Admin, Auditor, Careteam, CareteamNavigator, Company,
                     CompanyAdministrator, CompanyDocuments, CompanyEngineer,
                     CompanyGroup, Doctor, FinancialAdministrator,
                     HealthInsurance, Nurse, Patient, ProfessionalRegister,
                     Secretary, SecurityTechnician, Specialty,
                     TechnicalManager, Unit, UnitRoom)
from .permissions import TechnicalManagerPermission
from .serializers import (ProfessionalRegisterWithProfessionalObjectSerializer,
                          TechnicalManagerSerializer)
from .utils import (add_careteams_company_group,
                    handle_user_roles_and_is_active, new_user_instance)


class HealthInsuranceViewSet(viewsets.ModelViewSet):
    queryset = HealthInsurance.objects.all()
    serializer_class = serializers.HealthInsuranceSerializer
    pagination_class = BasePagination
    filter_backends = [DjangoFilterBackend]
    filterset_class = filters.HealthInsuranceFilter


class UnitViewSet(viewsets.ModelViewSet):
    queryset = Unit.objects.all()
    serializer_class = serializers.UnitSerializer
    pagination_class = BasePagination
    filter_backends = [DjangoFilterBackend]
    filterset_class = filters.UnitFilter


class UnitRoomViewSet(viewsets.ModelViewSet):
    queryset = UnitRoom.objects.all()
    serializer_class = serializers.UnitRoomSerializer
    pagination_class = BasePagination
    filter_backends = [DjangoFilterBackend]
    filterset_class = filters.UnitRoomFilter


class CompanyGroupViewSet(viewsets.ModelViewSet):
    """
    ViewSet for the Company class
    """
    queryset = CompanyGroup.objects.all()
    serializer_class = serializers.CompanyGroupSerializer
    pagination_class = BasePagination
    filterset_class = filters.CompanyGroupFilter
    permission_classes = [
        permissions.IsAuthenticated,
        custom_permissions.CompanyGroupPermission
    ]

    def get_queryset(self):
        user_request = self.request.user

        # Admin
        if user_request.active_role.role_name in ["admin", "financial_administrator"]:
            return self.queryset.all()

        # company adm
        elif user_request.active_role.role_name == "company_administrator":
            return self.queryset.filter(companies__company_adm__user_id=user_request).distinct()

        # company engineer
        elif user_request.active_role.role_name == "company_engineer":
            return self.queryset.filter(company_engineers__user_id=user_request).distinct()

        # security technician
        elif user_request.active_role.role_name == "security_technician":
            return self.queryset.filter(companies__careteams__security_technician_careteam__user_id=user_request).distinct()

        # secretary
        elif user_request.active_role.role_name == "secretary":
            return self.queryset.filter(companies__careteams__secretary_careteam__user_id=user_request).distinct()

        # doctor
        elif user_request.active_role.role_name == "doctor":
            return self.queryset.filter(companies__careteams__doctor_careteam__user_id=user_request).distinct()

        # nurse
        elif user_request.active_role.role_name == "nurse":
            return self.queryset.filter(companies__careteams__nurse_careteam__user_id=user_request).distinct()

        # auditor
        elif user_request.active_role.role_name == "auditor":
            return self.queryset.filter(companies__careteams__auditor_careteam__user_id=user_request).distinct()

        else:
            return self.queryset.none()

    @action(detail=True, methods=['post'],
            permission_classes=[permissions.IsAuthenticated, custom_permissions.CompanyGroupPermission])
    def add_professionals(self, request, pk=None):
        instance = self.get_object()
        professional_type = request.data.get('professional_type', None)
        professional_ids = request.data.get('professional_ids', [])

        if professional_type and professional_ids:
            types = {
                'doctors': Doctor,
                'nurses': Nurse,
                'secretaries': Secretary,
                'auditors': Auditor,
                'security-technicians': SecurityTechnician
            }

            if professional_type not in types.keys():
                return Response({"message": "Tipo de profissional inválido"})

            for professional_instance in types[professional_type].objects.filter(id__in=professional_ids):
                professional_instance.company_group_id.add(instance)
                add_careteams_company_group(
                    professional_instance, [instance.id])

        serializer = self.get_serializer(instance)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'],
            permission_classes=[permissions.IsAuthenticated, custom_permissions.CompanyGroupPermission])
    def add_companies(self, request, pk=None):
        instance = self.get_object()
        company_ids = request.data.get("company_ids", [])

        for company_id in company_ids:
            company = Company.objects.filter(id=company_id).first()
            if company:
                company.company_group_id = instance
                company.save()

        serializer = self.get_serializer(instance)
        return Response(serializer.data, status=status.HTTP_200_OK)


class CompanyViewSet(viewsets.ModelViewSet):
    """
    ViewSet for the Company class
    """
    queryset = Company.objects.all()
    serializer_class = serializers.CompanySerializer
    pagination_class = BasePagination
    filterset_class = filters.CompanyFilter

    def get_serializer_class(self):
        if self.request.method in permissions.SAFE_METHODS and self.request.query_params.get('view') == 'list':
            return serializers.CompanySerializerListView
        return self.serializer_class

    def get_queryset(self):
        user_request = self.request.user

        # Admin
        if user_request.active_role.role_name == "admin":
            return self.queryset.all()

        # Admin Financeiro
        if user_request.active_role.role_name == "financial_administrator":
            return self.queryset.all()

        # company adm
        elif user_request.active_role.role_name == "company_administrator":
            return self.queryset.filter(company_adm__user_id=user_request)

        # company engineer
        elif user_request.active_role.role_name == "company_engineer":
            return self.queryset.filter(company_engineer__user_id=user_request)

        # security technician
        elif user_request.active_role.role_name == "security_technician":
            return self.queryset.filter(careteams__security_technician_careteam__user_id=user_request).distinct()

        # doctor
        elif user_request.active_role.role_name == "doctor":
            return self.queryset.filter(
                careteams__coordinating_professional_id__doctor_register__user_id=user_request).distinct()

        else:
            return self.queryset.none()


class CompanyDocumentsViewSet(viewsets.ModelViewSet):
    queryset = CompanyDocuments.objects.all()
    serializer_class = serializers.CompanyDocumentsSerializer

    def create(self, request, *args, **kwargs):
        data = request.data
        document_bytes = data.get('document').read()

        file_instance = File()
        file_instance.file.save(
            data.get('document').name,
            io.BytesIO(document_bytes)
        )
        file_instance.save()

        data['company_id'] = data.get('company_id')
        data['file_id'] = file_instance.id
        serializer_instance = self.get_serializer(data=data)
        serializer_instance.is_valid(raise_exception=True)
        serializer_instance.save()

        return Response(serializer_instance.data, status=status.HTTP_201_CREATED)


class CareteamViewSet(viewsets.ModelViewSet):
    """
    ViewSet for the Careteam class
    """
    queryset = Careteam.objects.all()
    serializer_class = serializers.CareteamSerializerWithMembers
    permission_classes = [
        permissions.IsAuthenticated,
        custom_permissions.ManageCareteams,
        APIUserPermissions
    ]
    pagination_class = BasePagination
    filterset_class = CareteamFilter

    def get_serializer_class(self):
        if self.request.method in permissions.SAFE_METHODS and self.request.query_params.get('view') == 'list':
            return serializers.CareteamSerializerListView
        return self.serializer_class

    def get_queryset(self):
        user_request = self.request.user

        # Admin
        if user_request.active_role.role_name == "admin":
            return self.queryset.all()

        # company adm
        elif user_request.active_role.role_name == "company_administrator":
            return self.queryset.filter(company_id__company_adm__user_id=user_request)

        # secretary
        elif user_request.active_role.role_name == "secretary":
            return self.queryset.filter(secretary_careteam__user_id=user_request)

        # doctor
        elif user_request.active_role.role_name == "doctor":
            return self.queryset.filter(doctor_careteam__user_id=user_request)

        # nurse
        elif user_request.active_role.role_name == "nurse":
            return self.queryset.filter(nurse_careteam__user_id=user_request)

        # auditor
        elif user_request.active_role.role_name == "auditor":
            return self.queryset.filter(auditor_careteam__user_id=user_request)

        # security_technician
        elif user_request.active_role.role_name == "security_technician":
            return self.queryset.filter(security_technician_careteam__user_id=user_request)

        # API_USER
        elif user_request.active_role.role_name == 'api_user':
            return self.queryset.filter(company_id__access_company__user_id=user_request).distinct()

        else:
            return self.queryset.none()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        careteam = serializer.save()

        # add company groups related professionals
        company_group_id = careteam.company_id.company_group_id
        if company_group_id:
            careteam.doctor_careteam.set(company_group_id.doctors.all())
            careteam.nurse_careteam.set(company_group_id.nurses.all())
            careteam.secretary_careteam.set(company_group_id.secretaries.all())
            careteam.auditor_careteam.set(company_group_id.auditors.all())
            careteam.security_technician_careteam.set(
                company_group_id.security_technicians.all())
            careteam.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @action(methods=['get'], detail=True, url_name='navigators')
    def navigators(self, request, pk=None):
        careteam = Careteam.objects.filter(pk=pk).first()
        if careteam:
            response_data = serializers.CareteamSerializerWithMembers(
                careteam).data
            navigators = CareteamNavigator.objects.filter(careteam_id__id=pk)
            response_data["careteam_navigators"] = serializers.NavigatorsSerializer(
                navigators, many=True).data
            return Response(response_data, status=status.HTTP_200_OK)
        else:
            return Response({
                'detail': 'Não encontrado'
            }, status=status.HTTP_404_NOT_FOUND)


class NavigatorsViewSet(viewsets.ModelViewSet):
    """
    ViewSet for the Careteam Navigator class
    """
    queryset = CareteamNavigator.objects.all()
    serializer_class = serializers.NavigatorsSerializer
    pagination_class = BasePagination
    filterset_class = filters.NavigatorsFilter

    def get_queryset(self):
        user_request = self.request.user
        if user_request.active_role.role_name == "patient":
            return self.queryset.filter(careteam_id=user_request.patient.careteam_id.first().id)
        else:
            return self.queryset.all()

    def create(self, request, *args, **kwargs):
        for user in request.data["careteam_navigators"]:
            try:
                navigator_instance = self.get_serializer().create(user)
                response_serializer = serializers.CareteamSerializerWithMembers(
                    navigator_instance.careteam_id)
            except Exception as exc:
                return Response(exc.args[0], status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(response_serializer.data, status=status.HTTP_201_CREATED)

    def delete(self, request):
        ids = request.query_params.get('ids')
        for delete_id in ids.split(','):
            self.queryset.get(pk=delete_id).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class SpecialtyViewSet(viewsets.ModelViewSet):
    """
    ViewSet for the Speciality class
    """
    queryset = Specialty.objects.all()
    serializer_class = serializers.SpecialtySerializer
    permission_classes = [
        permissions.IsAuthenticated,
        custom_permissions.IsAdminOrReadOnly
    ]
    pagination_class = BasePagination
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = {
        "name": ["icontains"],
        "description": ["icontains"],
    }
    ordering_fields = '__all__'


class PatientViewSet(viewsets.ModelViewSet, ExportMixin):
    """
    ViewSet for the Patient class
    """
    queryset = Patient.objects.all()
    serializer_class = serializers.PatientSerializer
    export_serializer_class = serializers.ExportPatientSerializer
    pagination_class = BasePagination
    permission_classes = [
        APIUserPermissions,
        custom_permissions.ManagePatients
    ]
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_class = filters.PatientFilters
    ordering_fields = ['user_id__name', 'user_id__birth']

    def get_queryset(self):
        user_request = self.request.user

        # admin
        if user_request.active_role.role_name == 'admin':
            return self.queryset.all()

        # company adm
        elif user_request.active_role.role_name == 'company_administrator':
            return self.queryset.filter(careteam_id__company_id__company_adm__user_id=user_request).distinct()

        # patient
        elif user_request.active_role.role_name == 'patient':
            return self.queryset.filter(user_id=user_request)

        # secretary
        elif user_request.active_role.role_name == 'secretary':
            return self.queryset.filter(careteam_id__secretary_careteam__user_id=user_request).distinct()

        # doctor
        elif user_request.active_role.role_name == 'doctor':
            return self.queryset.filter(careteam_id__doctor_careteam__user_id=user_request).distinct()

        # nurse
        elif user_request.active_role.role_name == 'nurse':
            return self.queryset.filter(careteam_id__nurse_careteam__user_id=user_request).distinct()

        # securitytechnitian
        elif user_request.active_role.role_name == 'security_technician':
            return self.queryset.filter(careteam_id__security_technician_careteam__user_id=user_request).distinct()

        # auditor
        elif user_request.active_role.role_name == 'auditor':
            return self.queryset.filter(careteam_id__auditor_careteam__user_id=user_request).distinct()

        # API_USER
        elif user_request.active_role.role_name == 'api_user':
            return self.queryset.filter(careteam_id__company_id__access_company__user_id=user_request).distinct()

        else:
            return self.queryset.none()

    # def retrieve(self, request, *args, **kwargs):
    #     instance = self.get_object()
    #     ip = get_client_ip(request)
    #     current_user_role_instance = get_user_role_instance(request.user, request.user.active_role.role_name)
    #     print(ip, current_user_role_instance)
    #     serializer = self.get_serializer(instance)
    #     return Response(serializer.data)

    def get_serializer_class(self):
        serializer = self.serializer_class
        if self.request.method in permissions.SAFE_METHODS:
            if self.request.query_params.get('view') == 'with_medical':
                serializer = serializers.PatientWithMedicalRecordsSerializer
            elif self.request.query_params.get('view') == 'to_meeting':
                serializer = serializers.PatientToMeetingSerializer
            elif self.request.query_params.get('view') == 'meeting_request':
                serializer = serializers.PatientToRequestMeetingSerializer
            elif self.request.query_params.get('view') == 'list':
                serializer = serializers.PatientListSerializer
        return serializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        auditor = serializer.save()

        auditor_role = ActiveRole.objects.filter(role_name='patient').first()
        auditor.user_id.active_role = auditor_role
        auditor.user_id.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        patient = self.get_object()

        serializer = self.get_serializer(
            patient, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        self.perform_update(serializer)

        is_active = request.data.get('is_active', None)

        if is_active is not None:
            handle_user_roles_and_is_active(patient.user_id)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()

        if instance.patient_medical_record:
            if instance.patient_medical_record.patient_alerts_id:
                instance.patient_medical_record.patient_alerts_id.delete()

            if instance.patient_medical_record.patient_disease_id:
                instance.patient_medical_record.patient_disease_id.delete()

            if instance.patient_medical_record.patient_medication_id:
                instance.patient_medical_record.patient_medication_id.delete()

            if instance.patient_medical_record.patient_neoplasm_id:
                instance.patient_medical_record.patient_neoplasm_id.delete()

            if instance.patient_medical_record.patient_osteoporosis_id:
                instance.patient_medical_record.patient_osteoporosis_id.delete()

            if instance.patient_medical_record.patient_lifestyle_id:
                instance.patient_medical_record.patient_lifestyle_id.delete()

            if instance.patient_medical_record.patient_sarcopenia_id:
                instance.patient_medical_record.patient_sarcopenia_id.delete()

            if instance.patient_medical_record.patient_cardiovasc_id:
                instance.patient_medical_record.patient_cardiovasc_id.delete()

            if instance.patient_medical_record.patient_vaccines_id:
                instance.patient_medical_record.patient_vaccines_id.delete()

            if instance.patient_medical_record.patient_internal_information_id:
                instance.patient_medical_record.patient_internal_information_id.delete()

            if instance.patient_medical_record.diagnostic_hypothesis_medical_record.all().exists():
                instance.patient_medical_record.diagnostic_hypothesis_medical_record.all().delete()

            if instance.patient_medical_record.registered_by_patient_information.all().exists():
                instance.patient_medical_record.registered_by_patient_information.all().delete()

        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(methods=['get'], detail=True, url_name='activities')
    def activities(self, request, pk=None):
        activities = PatientActivity.objects.filter(patient_id=pk)
        page = self.paginate_queryset(activities)

        if page is not None:
            serializer = PatientActivitySerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = PatientActivitySerializer(activities, many=True)
        return Response(serializer.data)

    @action(methods=['post'], detail=False, url_name='patient_new_user')
    def new_user(self, request):
        return new_user_instance(self=self, request=request, role_name="patient", has_careteam=True)


class ProfessionalRegisterViewSet(viewsets.ModelViewSet, HistoricFromObjectMixin):
    """
    ViewSet for the ProfessionalRegister class
    """
    queryset = ProfessionalRegister.objects.all()
    serializer_class = serializers.ProfessionalRegisterSerializer
    filterset_class = filters.ProfessionalRegisterFilter
    permission_classes = [
        APIUserPermissions,
    ]

    def get_serializer_class(self):
        if self.request.query_params.get('view') == 'with_professional':
            return serializers.ProfessionalRegisterWithProfessionalObjectSerializer
        return self.serializer_class

    def create(self, request, *args, **kwargs):
        if 'register_type' not in request.data or 'register' not in request.data:
            return Response({"message": "Informações de registro incompletas"}, status=status.HTTP_400_BAD_REQUEST)

        profile_type = request.data.get('professional_type', None)
        instance = None
        register_default = True

        if profile_type:
            profile_types = {
                'doctor': Doctor,
                'nurse': Nurse,
                'security_technician': SecurityTechnician,
                'company_engineer': CompanyEngineer
            }
            if profile_type not in profile_types:
                return Response({"message": "Tipo de perfil inválido"}, status=status.HTTP_400_BAD_REQUEST)

            instance = profile_types[profile_type].objects.filter(id=request.data.get('professional_id')).first()
            if not instance:
                return Response({"message": "Perfil não encontrado"}, status=status.HTTP_404_NOT_FOUND)

            register_default = False if instance.professional_register_id.all().exists() else True

        try:
            state_id = State.objects.get(id=int(request.data.get('state_id')))

            professional_register = ProfessionalRegister.objects.create(
                register_type=request.data.get('register_type'),
                register=request.data.get('register'),
                additional_information=request.data.get('additional_information'),
                state_id=state_id,
                register_default=register_default,
                content_object=instance,
            )
        except:
            return Response({
                "message": "Não foi possível adicionar registro profissional"
            }, status=status.HTTP_400_BAD_REQUEST)

        return Response(
            ProfessionalRegisterWithProfessionalObjectSerializer(professional_register).data,
            status=status.HTTP_201_CREATED
        )

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()

        if "register_default" in request.data:
            if request.data.get("register_default"):
                professional_instance = instance.content_object
                professional_registers = professional_instance.professional_register_id.all().exclude(id=instance.id)
                for professional_register in professional_registers:
                    professional_register.register_default = False
                    professional_register.save()

        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        professional_register = self.get_object()

        meetings = Meeting.objects.filter(professional_id=professional_register)
        if meetings.exists():
            return Response({"message": "Não é possível apagar o registro pois já está ligado a uma consulta"},
                            status=status.HTTP_403_FORBIDDEN)

        exam_orders = ExamOrder.objects.filter(professional_id=professional_register)
        medical_certificates = MedicalCertificate.objects.filter(professional_id=professional_register)
        occcupational_health_certificates = OccupationalHealthCertificate.objects.filter(
            Q(professional_id=professional_register) | Q(coordinating_professional_id=professional_register)
        )
        prescriptions = Prescription.objects.filter(professional_id=professional_register)

        harmful_agents = HarmfulAgent.objects.filter(
            technical_manager_id__professional_register_id=professional_register
        )

        if exam_orders.exists() or medical_certificates.exists() or occcupational_health_certificates.exists() or \
                prescriptions.exists() or harmful_agents.exists():
            return Response({
                "message": "Não é possível apagar o registro pois já está ligado a um documento no sistema"
            }, status=status.HTTP_403_FORBIDDEN)

        self.perform_destroy(professional_register)
        return Response(status=status.HTTP_204_NO_CONTENT)


class DoctorViewSet(viewsets.ModelViewSet, AddProfessionalToCompanyGroup):
    """
    ViewSet for the Doctor class
    """
    queryset = Doctor.objects.all()
    serializer_class = serializers.DoctorSerializer
    pagination_class = BasePagination
    filterset_class = filters.DoctorFilter
    permission_classes = [
        APIUserPermissions,
        custom_permissions.ManageCareteams
    ]

    def get_serializer_class(self):
        if self.request.method in permissions.SAFE_METHODS and self.request.query_params.get('view') == 'list':
            return serializers.DoctorSerializerListView
        return self.serializer_class

    def get_queryset(self):
        user_request = self.request.user

        # admin
        if user_request.active_role.role_name == 'admin':
            return self.queryset.all().distinct()

        # company adm
        elif user_request.active_role.role_name == 'company_administrator':
            return self.queryset.filter(careteam_id__company_id__company_adm__user_id=user_request).distinct()

        # patient
        elif user_request.active_role.role_name == 'patient':
            return self.queryset.filter(careteam_id__patient_careteam__user_id=user_request).distinct()

        # secretary
        elif user_request.active_role.role_name == 'secretary':
            return self.queryset.filter(careteam_id__secretary_careteam__user_id=user_request).distinct()

        # doctor
        elif user_request.active_role.role_name == 'doctor':
            return self.queryset.filter(careteam_id__doctor_careteam__user_id=user_request).distinct()

        # nurse
        elif user_request.active_role.role_name == 'nurse':
            return self.queryset.filter(careteam_id__nurse_careteam__user_id=user_request).distinct()

        # securitytechnitian
        elif user_request.active_role.role_name == 'security_technician':
            return self.queryset.filter(careteam_id__security_technician_careteam__user_id=user_request).distinct()

        # auditor
        elif user_request.active_role.role_name == 'auditor':
            return self.queryset.filter(careteam_id__auditor_careteam__user_id=user_request).distinct()

        # API_USER
        elif user_request.active_role.role_name == 'api_user':
            return self.queryset.filter(careteam_id__company_id__access_company__user_id=user_request).distinct()

        else:
            return self.queryset.none()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        doctor = serializer.save()

        doctor_role = ActiveRole.objects.filter(role_name='doctor').first()
        doctor.user_id.active_role = doctor_role
        doctor.user_id.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        doctor = self.get_object()
        serializer = self.get_serializer(doctor, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        self.perform_update(serializer)

        is_active = request.data.get('is_active', None)

        if is_active is not None:
            handle_user_roles_and_is_active(doctor.user_id)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        doctor = self.get_object()

        try:
            # Clear the professional records to totally delete
            doctor.professional_register_id.clear()
        except:
            return Response({
                "message": "Não é possível excluir este(a) médico(a) pois ele tem registro profissional em uso"
            }, status=status.HTTP_403_FORBIDDEN)

        self.perform_destroy(doctor)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(methods=['post'], detail=False, url_name='doctor_new_user')
    def new_user(self, request):
        return new_user_instance(self=self, request=request, role_name="doctor", has_careteam=True)


class NurseViewSet(viewsets.ModelViewSet, AddProfessionalToCompanyGroup):
    """
    ViewSet for the Nurse class
    """
    queryset = Nurse.objects.all()
    serializer_class = serializers.NurseSerializer
    pagination_class = BasePagination
    filterset_class = filters.NurseFilter
    permission_classes = [
        APIUserPermissions,
        custom_permissions.ManageCareteams
    ]

    def get_serializer_class(self):
        if self.request.method in permissions.SAFE_METHODS and self.request.query_params.get('view') == 'list':
            return serializers.NurseSerializerListView
        return self.serializer_class

    def get_queryset(self):
        user_request = self.request.user

        # admin
        if user_request.active_role.role_name == 'admin':
            return self.queryset.all()

        # company adm
        elif user_request.active_role.role_name == 'company_administrator':
            return self.queryset.filter(careteam_id__company_id__company_adm__user_id=user_request).distinct()

        # patient
        elif user_request.active_role.role_name == 'patient':
            return self.queryset.filter(careteam_id__patient_careteam__user_id=user_request).distinct()

        # secretary
        elif user_request.active_role.role_name == 'secretary':
            return self.queryset.filter(careteam_id__secretary_careteam__user_id=user_request).distinct()

        # doctor
        elif user_request.active_role.role_name == 'doctor':
            return self.queryset.filter(careteam_id__doctor_careteam__user_id=user_request).distinct()

        # nurse
        elif user_request.active_role.role_name == 'nurse':
            return self.queryset.filter(careteam_id__nurse_careteam__user_id=user_request).distinct()

        # securitytechnitian
        elif user_request.active_role.role_name == 'security_technician':
            return self.queryset.filter(careteam_id__security_technician_careteam__user_id=user_request).distinct()

        # auditor
        elif user_request.active_role.role_name == 'auditor':
            return self.queryset.filter(careteam_id__auditor_careteam__user_id=user_request).distinct()

        # API_USER
        elif user_request.active_role.role_name == 'api_user':
            return self.queryset.filter(careteam_id__company_id__access_company__user_id=user_request).distinct()

        else:
            return self.queryset.none()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        nurse = serializer.save()

        # Insert professional register manually because GenericField don't accept them serialized
        if request.data.get('professional_register_id'):
            for register in request.data.get('professional_register_id'):
                try:
                    nurse.professional_register_id.create(
                        register_type=register['register_type'],
                        register=register['register'],
                        additional_information=register['additional_information'],
                        register_default=register['register_default']
                    )
                except:
                    return Response({"message": "Erro ao salvar registro profissional"},
                                    status=status.HTTP_400_BAD_REQUEST)

        nurse.save()

        nurse_role = ActiveRole.objects.filter(role_name='nurse').first()
        nurse.user_id.active_role = nurse_role
        nurse.user_id.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        nurse = self.get_object()
        serializer = self.get_serializer(
            nurse, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        # Create new professional registers
        if request.data.get('professional_register_id'):
            for register_request in request.data.get('professional_register_id'):
                try:
                    nurse.professional_register_id.create(
                        register_type=register_request['register_type'],
                        register=register_request['register'],
                        additional_information=register_request['additional_information'],
                        register_default=False
                    )
                except:
                    return Response({"message": "Erro ao salvar registro profissional"},
                                    status=status.HTTP_400_BAD_REQUEST)

        self.perform_update(serializer)

        is_active = request.data.get('is_active', None)

        if is_active is not None:
            handle_user_roles_and_is_active(nurse.user_id)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        nurse = self.get_object()

        try:
            # Clear the professional records to totally delete
            nurse.professional_register_id.clear()
        except:
            return Response({
                "message": "Não é possível excluir este(a) enfermeiro(a) pois ele tem registro profissional em uso"
            }, status=status.HTTP_403_FORBIDDEN)

        self.perform_destroy(nurse)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(methods=['post'], detail=False, url_name='nurse_new_user')
    def new_user(self, request):
        return new_user_instance(self=self, request=request, role_name="nurse", has_careteam=True)


class SecretaryViewSet(viewsets.ModelViewSet, AddProfessionalToCompanyGroup):
    """
    ViewSet for the Secretary class
    """
    queryset = Secretary.objects.all()
    serializer_class = serializers.SecretarySerializer
    pagination_class = BasePagination
    filterset_class = filters.SecretaryFilter
    permission_classes = [
        APIUserPermissions,
        custom_permissions.ManageCareteams
    ]

    def get_serializer_class(self):
        if self.request.method in permissions.SAFE_METHODS and self.request.query_params.get('view') == 'list':
            return serializers.SecretarySerializerListView
        return self.serializer_class

    def get_queryset(self):
        user_request = self.request.user

        # admin
        if user_request.active_role.role_name == 'admin':
            return self.queryset.all()

        # company adm
        elif user_request.active_role.role_name == 'company_administrator':
            return self.queryset.filter(careteam_id__company_id__company_adm__user_id=user_request).distinct()

        # doctor
        elif user_request.active_role.role_name == 'doctor':
            return self.queryset.filter(careteam_id__doctor_careteam__user_id=user_request).distinct()

        # nurse
        elif user_request.active_role.role_name == 'nurse':
            return self.queryset.filter(careteam_id__nurse_careteam__user_id=user_request).distinct()

        # secretary
        elif user_request.active_role.role_name == 'secretary':
            return self.queryset.filter(user_id=user_request)

        # securitytechnitian
        elif user_request.active_role.role_name == 'security_technician':
            return self.queryset.filter(careteam_id__security_technician_careteam__user_id=user_request).distinct()

        # auditor
        elif user_request.active_role.role_name == 'auditor':
            return self.queryset.filter(careteam_id__auditor_careteam__user_id=user_request).distinct()

        # API_USER
        elif user_request.active_role.role_name == 'api_user':
            return self.queryset.filter(careteam_id__company_id__access_company__user_id=user_request).distinct()

        else:
            return self.queryset.none()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        secretary = serializer.save()

        secretary_role = ActiveRole.objects.filter(
            role_name='secretary').first()
        secretary.user_id.active_role = secretary_role
        secretary.user_id.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        secretary = self.get_object()

        serializer = self.get_serializer(
            secretary, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        self.perform_update(serializer)

        is_active = request.data.get('is_active', None)

        if is_active is not None:
            handle_user_roles_and_is_active(secretary.user_id)

        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(methods=['post'], detail=False, url_name='secretary_new_user')
    def new_user(self, request):
        return new_user_instance(self=self, request=request, role_name="secretary", has_careteam=True)


class AuditorViewSet(viewsets.ModelViewSet, AddProfessionalToCompanyGroup):
    """
    ViewSet for the Auditor class
    """
    queryset = Auditor.objects.all()
    serializer_class = serializers.AuditorSerializer
    pagination_class = BasePagination
    filterset_class = filters.AuditorFilter
    permission_classes = [
        APIUserPermissions,
        custom_permissions.ManageCareteams
    ]

    def get_serializer_class(self):
        if self.request.method in permissions.SAFE_METHODS and self.request.query_params.get('view') == 'list':
            return serializers.AuditorSerializerListView
        return self.serializer_class

    def get_queryset(self):
        user_request = self.request.user

        # admin
        if user_request.active_role.role_name == 'admin':
            return self.queryset.all()

        # company adm
        elif user_request.active_role.role_name == 'company_administrator':
            return self.queryset.filter(careteam_id__company_id__company_adm__user_id=user_request).distinct()

        # doctor
        elif user_request.active_role.role_name == 'doctor':
            return self.queryset.filter(careteam_id__doctor_careteam__user_id=user_request).distinct()

        # nurse
        elif user_request.active_role.role_name == 'nurse':
            return self.queryset.filter(careteam_id__nurse_careteam__user_id=user_request).distinct()

        # secretary
        elif user_request.active_role.role_name == 'secretary':
            return self.queryset.filter(user_id=user_request)

        # securitytechnitian
        elif user_request.active_role.role_name == 'security_technician':
            return self.queryset.filter(careteam_id__security_technician_careteam__user_id=user_request).distinct()

        # auditor
        elif user_request.active_role.role_name == 'auditor':
            return self.queryset.filter(user_id=user_request)

        # API_USER
        elif user_request.active_role.role_name == 'api_user':
            return self.queryset.filter(careteam_id__company_id__access_company__user_id=user_request).distinct()

        else:
            return self.queryset.none()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        auditor = serializer.save()

        auditor_role = ActiveRole.objects.filter(role_name='auditor').first()
        auditor.user_id.active_role = auditor_role
        auditor.user_id.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        auditor = self.get_object()

        serializer = self.get_serializer(
            auditor, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        self.perform_update(serializer)

        is_active = request.data.get('is_active', None)

        if is_active is not None:
            handle_user_roles_and_is_active(auditor.user_id)

        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(methods=['post'], detail=False, url_name='auditor_new_user')
    def new_user(self, request):
        return new_user_instance(self=self, request=request, role_name="auditor", has_careteam=True)


class SecurityTechnicianViewSet(viewsets.ModelViewSet, AddProfessionalToCompanyGroup):
    """
    ViewSet for the Security Technician class
    """
    queryset = SecurityTechnician.objects.all()
    serializer_class = serializers.SecurityTechnicianSerializer
    pagination_class = BasePagination
    filterset_class = filters.SecurityTechnicianFilter
    permission_classes = [
        APIUserPermissions,
        custom_permissions.ManageCareteams
    ]

    def get_serializer_class(self):
        if self.request.method in permissions.SAFE_METHODS and self.request.query_params.get('view') == 'list':
            return serializers.SecurityTechnicianSerializerListView
        return self.serializer_class

    def get_queryset(self):
        user_request = self.request.user

        # admin
        if user_request.active_role.role_name == 'admin':
            return self.queryset.all()

        # doctor
        elif user_request.active_role.role_name == 'doctor':
            return self.queryset.filter(careteam_id__doctor_careteam__user_id=user_request).distinct()

        # nurse
        elif user_request.active_role.role_name == 'nurse':
            return self.queryset.filter(careteam_id__nurse_careteam__user_id=user_request).distinct()

        # secretary
        elif user_request.active_role.role_name == 'secretary':
            return self.queryset.filter(user_id=user_request)

        # securitytechnitian
        elif user_request.active_role.role_name == 'security_technician':
            return self.queryset.filter(careteam_id__security_technician_careteam__user_id=user_request).distinct()

        # API_USER
        elif user_request.active_role.role_name == 'api_user':
            return self.queryset.filter(
                careteam_id__company_id__access_sucurity_technician__user_id=user_request).distinct()

        else:
            return self.queryset.none()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        security_technician = serializer.save()

        security_technician_role = ActiveRole.objects.filter(
            role_name='security_technician').first()
        security_technician.user_id.active_role = security_technician_role
        security_technician.user_id.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        security_technician = self.get_object()

        serializer = self.get_serializer(
            security_technician, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        self.perform_update(serializer)

        is_active = request.data.get('is_active', None)

        if is_active is not None:
            handle_user_roles_and_is_active(
                security_technician.user_id)

        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(methods=['post'], detail=False, url_name='security_technician_new_user')
    def new_user(self, request):
        return new_user_instance(self=self, request=request, role_name="security_technician", has_careteam=True)


class FinancialAdministratorViewSet(viewsets.ModelViewSet):
    """
    ViewSet for the FinancialAdministrator class
    """
    queryset = FinancialAdministrator.objects.all()
    serializer_class = serializers.FinancialAdministratorSerializer
    pagination_class = BasePagination
    filterset_class = filters.FinancialAdministratorFilter
    permission_classes = [
        APIUserPermissions,
        custom_permissions.FinancialAdminOrCpfPermission('023.966.269-57')  # Hard coded CPF
    ]

    def get_queryset(self):
        user_request = self.request.user

        # admin
        if user_request.active_role.role_name == 'admin':
            return self.queryset.all()

        # company adm
        elif user_request.active_role.role_name == 'company_administrator':
            return self.queryset.filter(careteam_id__company_id__company_adm__user_id=user_request).distinct()

        # financial adm
        elif user_request.active_role.role_name == 'financial_administrator':
            return self.queryset.filter(user_id=user_request)

        # API_USER
        elif user_request.active_role.role_name == 'api_user':
            return self.queryset.filter(careteam_id__company_id__access_company__user_id=user_request).distinct()

        else:
            return self.queryset.none()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        financial_adm = serializer.save()

        financial_adm_role = ActiveRole.objects.filter(
            role_name='financial_administrator').first()
        financial_adm.user_id.active_role = financial_adm_role
        financial_adm.user_id.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        financial_adm = self.get_object()

        serializer = self.get_serializer(
            financial_adm, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        self.perform_update(serializer)

        is_active = request.data.get('is_active', None)

        if is_active is not None:
            handle_user_roles_and_is_active(financial_adm.user_id)

        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(methods=['post'], detail=False, url_name='financial_adm_new_user')
    def new_user(self, request):
        return new_user_instance(self=self, request=request, role_name="financial_administrator", has_careteam=False)


class CompanyAdministratorViewSet(viewsets.ModelViewSet):
    """
    ViewSet for the FinancialAdministrator class
    """
    queryset = CompanyAdministrator.objects.all()
    serializer_class = serializers.CompanyAdministratorSerializer
    pagination_class = BasePagination
    filterset_class = filters.CompanyAdministratorFilter
    permission_classes = [
        APIUserPermissions,
        custom_permissions.IsAdminOrReadOnly
    ]

    def get_queryset(self):
        user_request = self.request.user

        # admin
        if user_request.active_role.role_name == 'admin':
            return self.queryset.all()

        # company adm
        elif user_request.active_role.role_name == 'company_administrator':
            return self.queryset.filter(user_id=user_request)

        # API_USER
        elif user_request.active_role.role_name == 'api_user':
            return self.queryset.filter(company_id__access_company__user_id=user_request).distinct()

        else:
            return self.queryset.none()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        company_adm = serializer.save()

        company_adm_role = ActiveRole.objects.filter(
            role_name='company_administrator').first()
        company_adm.user_id.active_role = company_adm_role
        company_adm.user_id.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        company_adm = self.get_object()

        serializer = self.get_serializer(
            company_adm, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        self.perform_update(serializer)

        is_active = request.data.get('is_active', None)

        if is_active is not None:
            handle_user_roles_and_is_active(company_adm.user_id)

        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(methods=['post'], detail=False, url_name='company_adm_new_user')
    def new_user(self, request):
        if not request.data.get('company_id'):
            return Response({"message": "Informe a empresa a ser adicionado"}, status=status.HTTP_400_BAD_REQUEST)

        send_during_business_hour = self.request.data.get('send_during_business_hour', True)
        user = serializers.UserSerializer(
            data=request.data, context={'request': request, 'send_during_business_hour': send_during_business_hour})
        user.is_valid(raise_exception=True)
        user = user.save()

        role = ActiveRole.objects.filter(
            role_name="company_administrator").first()
        user.active_role = role
        user.save()

        instance = self.get_serializer(
            data={"user_id": user.id, "company_id": request.data.get('company_id')})
        instance.is_valid(raise_exception=True)
        instance.save()

        return Response(instance.data, status=status.HTTP_201_CREATED)


class CompanyEngineerViewSet(viewsets.ModelViewSet):
    """
    ViewSet for the FinancialAdministrator class
    """
    queryset = CompanyEngineer.objects.all()
    serializer_class = serializers.CompanyEngineerSerializer
    pagination_class = BasePagination
    filterset_class = filters.EngineerFilter
    permission_classes = [
        APIUserPermissions,
        custom_permissions.IsAdminOrCompanyAdminOrReadOnly
    ]

    def get_queryset(self):
        user_request = self.request.user

        # admin
        if user_request.active_role.role_name == 'admin':
            return self.queryset.all()

        # company adm
        elif user_request.active_role.role_name == 'company_administrator':
            return self.queryset.filter(company_id__company_adm__user_id=user_request)

        # doctor
        elif user_request.active_role.role_name == 'doctor':
            return self.queryset.filter(company_id__careteams__doctor_careteam__user_id=user_request).distinct()

        # nurse
        elif user_request.active_role.role_name == 'nurse':
            return self.queryset.filter(company_id__careteams__nurse_careteam__user_id=user_request).distinct()

        # secretary
        elif user_request.active_role.role_name == 'secretary':
            return self.queryset.filter(user_id=user_request)

        # company adm
        elif user_request.active_role.role_name == 'company_engineer':
            return self.queryset.all()

        # API_USER
        elif user_request.active_role.role_name == 'api_user':
            return self.queryset.filter(company_id__access_company__user_id=user_request).distinct()

        else:
            return self.queryset.none()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        company_engineer = serializer.save()

        company_engineer_role = ActiveRole.objects.filter(
            role_name='company_engineer').first()
        company_engineer.user_id.active_role = company_engineer_role
        company_engineer.user_id.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        company_engineer = self.get_object()

        serializer = self.get_serializer(
            company_engineer, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)

        self.perform_update(serializer)

        is_active = request.data.get('is_active', None)

        if is_active is not None:
            handle_user_roles_and_is_active(
                company_engineer.user_id)

        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(methods=['post'], detail=False, url_name='company_engineer_new_user')
    def new_user(self, request):
        if not request.data.get('company_id'):
            return Response({"message": "Informe a empresa a ser adicionado"}, status=status.HTTP_400_BAD_REQUEST)
        send_during_business_hour = self.request.data.get('send_during_business_hour', True)
        user = serializers.UserSerializer(
            data=request.data, context={'request': request, 'send_during_business_hour': send_during_business_hour})
        user.is_valid(raise_exception=True)
        user = user.save()

        role = ActiveRole.objects.filter(role_name="company_engineer").first()
        user.active_role = role
        user.save()

        instance = self.get_serializer(
            data={"user_id": user.id, "company_id": request.data.get('company_id')})
        instance.is_valid(raise_exception=True)
        instance.save()

        return Response(instance.data, status=status.HTTP_201_CREATED)


class AdminViewSet(viewsets.ModelViewSet):
    """
    ViewSet for the FinancialAdministrator class
    """
    queryset = Admin.objects.all()
    serializer_class = serializers.AdminSerializer
    pagination_class = BasePagination
    filterset_class = filters.AdminFilter

    def get_queryset(self):
        user_request = self.request.user

        # admin
        if user_request.active_role.role_name == 'admin':
            return self.queryset

        else:
            return self.queryset.none()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        admin = serializer.save()

        admin_role = ActiveRole.objects.filter(role_name='admin').first()
        admin.user_id.active_role = admin_role
        admin.user_id.save()

        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        admin = self.get_object()

        serializer = self.get_serializer(
            admin, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        is_active = request.data.get('is_active', None)

        if is_active is not None:
            handle_user_roles_and_is_active(admin.user_id)

        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(methods=['post'], detail=False, url_name='admin_new_user')
    def new_user(self, request):
        return new_user_instance(self=self, request=request, role_name="admin", has_careteam=False)


class ProfessionalsByRegisterView(generics.ListAPIView,
                                  generics.RetrieveAPIView,
                                  viewsets.ViewSet):
    queryset = ProfessionalRegister.objects.all()
    serializer_class = serializers.ProfessionalsByRegisterSerializer

    def get_queryset(self):
        user_request = self.request.user

        # admin
        if user_request.active_role.role_name == 'admin':
            queryset = self.queryset

        # company administrator
        elif user_request.active_role.role_name == 'company_administrator':
            queryset = self.queryset.filter(
                Q(
                    doctor_register__careteam_id__company_id__company_adm__user_id=user_request,
                    doctor_register__is_active=True,
                    register_default=True
                ) |
                Q(
                    nurse_register__careteam_id__company_id__company_adm__user_id=user_request,
                    nurse_register__is_active=True,
                    register_default=True
                )
            ).distinct()

            # secretary
        elif user_request.active_role.role_name == 'secretary':
            queryset = self.queryset.filter(
                Q(
                    doctor_register__careteam_id__secretary_careteam__user_id=user_request,
                    doctor_register__is_active=True,
                    register_default=True
                ) |
                Q(
                    nurse_register__careteam_id__secretary_careteam__user_id=user_request,
                    nurse_register__is_active=True,
                    register_default=True
                )
            ).distinct()

        # doctor
        elif user_request.active_role.role_name == 'doctor':
            queryset = self.queryset.filter(
                Q(
                    doctor_register__careteam_id__doctor_careteam__user_id=user_request,
                    doctor_register__is_active=True,
                    register_default=True
                ) |
                Q(
                    nurse_register__careteam_id__doctor_careteam__user_id=user_request,
                    nurse_register__is_active=True,
                    register_default=True
                )
            ).distinct()

        # nurse
        elif user_request.active_role.role_name == 'nurse':
            queryset = self.queryset.filter(
                Q(
                    doctor_register__careteam_id__nurse_careteam__user_id=user_request,
                    doctor_register__is_active=True,
                    register_default=True
                ) |
                Q(
                    nurse_register__careteam_id__nurse_careteam__user_id=user_request,
                    nurse_register__is_active=True,
                    register_default=True
                )
            ).distinct()

        # API_USER
        elif user_request.active_role.role_name == 'api_user':
            queryset = self.queryset.filter(
                Q(
                    doctor_register__careteam_id__company_id__access_company__user_id=user_request,
                    doctor_register__is_active=True,
                    register_default=True
                ) |
                Q(
                    nurse_register__careteam_id__company_id__access_company__user_id=user_request,
                    nurse_register__is_active=True,
                    register_default=True
                )
            ).distinct()

        else:
            queryset = self.queryset.none()

        if careteam_id := self.request.query_params.get('careteam_id'):
            queryset = queryset.filter(
                Q(doctor_register__schedule_id__careteam=careteam_id) |
                Q(nurse_register__schedule_id__careteam=careteam_id)
            )

        if param_date := self.request.query_params.get('date'):
            date = dateutil.parser.parse(param_date, dayfirst=True)

            queryset = queryset.filter(
                Q(doctor_register__schedule_id__start__date=date) |
                Q(nurse_register__schedule_id__start__date=date)
            )

        return queryset


class TechnicalManagerViewSet(viewsets.ModelViewSet, HistoricFromObjectMixin):
    queryset = TechnicalManager.objects.all()
    serializer_class = TechnicalManagerSerializer
    pagination_class = BasePagination
    permission_classes = [
        permissions.IsAuthenticated,
        TechnicalManagerPermission
    ]
    filterset_class = filters.TechnicalManagerFilter

class DoctorSpecialtiesView(APIView):
    def get(self, request, doctor_id):
        try:
            doctor = Doctor.objects.get(id=doctor_id)
            specialties = doctor.specialty_id.all()
            specialty_data = [{'id': specialty.id, 'name': specialty.name} for specialty in specialties]
            return Response(specialty_data)
        except Doctor.DoesNotExist:
            return Response(status=404)
