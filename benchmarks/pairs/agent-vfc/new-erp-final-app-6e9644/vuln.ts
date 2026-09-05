// Provenance: Sachin-Salgar/NEW_ERP_FINAL  (vuln).
// repo: Sachin-Salgar/NEW_ERP_FINAL
// commit: 08976c5d7a07b0663669b875b4507446199f85d7
// parent: 08976c5d7a07b0663669b875b4507446199f85d7
// commit_url: https://github.com/Sachin-Salgar/NEW_ERP_FINAL/commit/6e9644c81ce3fb356669157182a5ef09a70c4b59
// cve: 
// license: Apache-2.0
// function: origin
// relpath: src/presentation/http/app.ts
// provenance: agent
// mechanism: permissive_default

export async function createApplication(config: AppConfig, providedPool?: Pool): Promise<FastifyInstance> {
  const app = Fastify({
    logger: createLogger(config),
    requestIdHeader: 'x-request-id',
    requestIdLogLabel: 'requestId',
    ignoreTrailingSlash: true,
    ajv: {
      customOptions: {
        allErrors: true,
        coerceTypes: true,
        removeAdditional: false,
      },
    },
  });

  const pool = providedPool ?? createDatabasePool(config);
  const repository = new IdentityAwarePostgresPlatformRepository(pool);
  const passwordHasher = new BcryptPasswordHasher();
  const jwtTokenService = new JwtTokenService(config);
  const authService = new AuthenticationService(repository, passwordHasher, jwtTokenService);
  const authorizationService = new AuthorizationService(repository);
  const branchService = new BranchService(repository);
  const coreEnterpriseService = new CoreEnterpriseService(repository);
  const locationService = new LocationService(repository);
  const moduleAccessService = new ModuleAccessService(pool);
  const registrationService = new UserRegistrationService(repository, passwordHasher);
  const tenantMembershipService = new TenantMembershipService(repository);

  app.decorate('appConfig', config);
  app.decorate('authService', authService);
  app.decorate('authorizationService', authorizationService);
  app.decorate('branchService', branchService);
  app.decorate('coreEnterpriseService', coreEnterpriseService);
  app.decorate('locationService', locationService);
  app.decorate('moduleAccessService', moduleAccessService);
  app.decorate('registrationService', registrationService);
  app.decorate('jwtTokenService', jwtTokenService);
  app.decorate('tenantMembershipService', tenantMembershipService);

  await app.register(cors, {
    origin: (origin, callback) => {
      callback(null, isCorsOriginAllowed(config, origin));
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-tenant-id'],
    credentials: true,
    optionsSuccessStatus: 204,
  });

  app.setErrorHandler(buildErrorHandler(config));

  await app.register(healthRoutes, { prefix: config.API_PREFIX });
  await app.register(authRoutes, { prefix: config.API_PREFIX });
  await app.register(rbacRoutes, { prefix: config.API_PREFIX });
  await app.register(branchRoutes, { prefix: config.API_PREFIX });
  await app.register(coreEnterpriseRoutes, { prefix: config.API_PREFIX });
  await app.register(locationRoutes, { prefix: config.API_PREFIX });

  return app;
}
