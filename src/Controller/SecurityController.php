<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Validator\Validator\ValidatorInterface;

#[Route('/api')]
class SecurityController extends AbstractController
{
    #[Route('/register', name: 'app_register', methods: ['POST'])]
    public function register(
        Request $request, 
        UserPasswordHasherInterface $passwordHasher,
        EntityManagerInterface $entityManager,
        ValidatorInterface $validator
    ): JsonResponse {
        $data = json_decode($request->getContent(), true);
        
        if (!isset($data['email']) || !isset($data['password']) || !isset($data['name'])) {
            return $this->json(['message' => 'Données manquantes'], Response::HTTP_BAD_REQUEST);
        }
        
        // Vérifier si l'utilisateur existe déjà
        $existingUser = $entityManager->getRepository(User::class)->findOneBy(['email' => $data['email']]);
        if ($existingUser) {
            return $this->json(['message' => 'Cet email est déjà utilisé'], Response::HTTP_BAD_REQUEST);
        }
        
        $user = new User();
        $user->setEmail($data['email']);
        $user->setName($data['name']);
        
        // Valider l'entité
        $errors = $validator->validate($user);
        if (count($errors) > 0) {
            $errorMessages = [];
            foreach ($errors as $error) {
                $errorMessages[] = $error->getMessage();
            }
            return $this->json(['message' => 'Validation échouée', 'errors' => $errorMessages], Response::HTTP_BAD_REQUEST);
        }
        
        // Encoder le mot de passe
        $hashedPassword = $passwordHasher->hashPassword($user, $data['password']);
        $user->setPassword($hashedPassword);
        
        // Sauvegarder l'utilisateur
        $entityManager->persist($user);
        $entityManager->flush();
        
        return $this->json([
            'message' => 'Utilisateur créé avec succès',
            'user' => [
                'id' => $user->getId(),
                'email' => $user->getEmail(),
                'name' => $user->getName()
            ]
        ], Response::HTTP_CREATED);
    }

    #[Route('/user', name: 'app_current_user', methods: ['GET'])]
    public function currentUser(): JsonResponse
    {
        /** @var User $user */
        $user = $this->getUser();
        
        if (!$user) {
            return $this->json(['message' => 'Non authentifié'], Response::HTTP_UNAUTHORIZED);
        }
        
        return $this->json([
            'user' => [
                'id' => $user->getId(),
                'email' => $user->getEmail(),
                'name' => $user->getName(),
                'roles' => $user->getRoles()
            ]
        ]);
    }
}